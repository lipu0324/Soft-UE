#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class FaultPort : public IPacketPort {
public:
    FaultPort(IPacketPort& lower,size_t drops) : lower_(lower), remaining_(drops) {}
    SendResult try_send(const Frame& frame) override {
        if (remaining_) { --remaining_; ++dropped; return SendResult::Accepted; }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    size_t dropped=0;
private:
    IPacketPort& lower_;
    size_t remaining_;
};

class BlockedPort : public IPacketPort {
public:
    explicit BlockedPort(IPacketPort& lower) : lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        ++attempts;
        return blocked_ ? SendResult::WouldBlock : lower_.try_send(frame);
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { writable_=std::move(callback); }
    void unblock() { blocked_=false; if (writable_) writable_(); }
    size_t attempts=0;
private:
    IPacketPort& lower_;
    Writable writable_;
    bool blocked_=true;
};

void backpressure_case() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& a=fabric.add_host(1); auto& b=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    BlockedPort port(a);
    PdsHost host_a(1,loop,trace,port),host_b(2,loop,trace,b);
    Endpoint source(1,host_a,loop,trace),target(2,host_b,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2;
    source.submit(noop);
    loop.run_until(1000);
    CHECK(port.attempts==1); // No zero-time busy polling while blocked.
    Completion completion{}; CHECK(!source.poll_completion(completion));
    port.unblock(); loop.run_until(kMillisecond/2);
    CHECK(source.poll_completion(completion)); CHECK(completion.status==CompletionStatus::Success);
    source.close(); target.close(); host_a.close(); host_b.close();
    port.unblock(); // A stale backend notification cannot resurrect a closed host.
    CHECK(loop.pending()==0);
}

void run_case(size_t forward_drops,size_t reverse_drops,bool succeeds) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& a=fabric.add_host(1); auto& b=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    FaultPort forward(a,forward_drops), reverse(b,reverse_drops);
    PdsHost host_a(1,loop,trace,forward),host_b(2,loop,trace,reverse);
    Endpoint source(1,host_a,loop,trace),target(2,host_b,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,4096,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=region.key;
    write.payload={1,2,3,4}; source.submit(write);
    loop.run_until(100*kMillisecond,10000);
    Completion completion{}; CHECK(source.poll_completion(completion));
    CHECK(completion.status==(succeeds?CompletionStatus::Success:CompletionStatus::Timeout));
    CHECK(!source.poll_completion(completion));
    if (succeeds) CHECK(target.memory().read(1,1,region.key,0,4)==write.payload);
    if (forward_drops) CHECK(forward.dropped>0);
    if (reverse_drops) CHECK(reverse.dropped>0);
    source.close(); target.close(); host_a.close(); host_b.close();
    CHECK(loop.pending()==0);
}
int main() {
    try {
        run_case(1,0,true); // Lost SYN/data must be recovered by the original PDC RTO.
        run_case(0,2,true); // Lose both the transport ACK and first semantic response.
        run_case(1000,0,false); // Retry exhaustion must not busy-loop at one timestamp.
        backpressure_case();
        std::cout << "PASS: lost SYN/data, lost ACK/response, bounded permanent failure and timer cleanup\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
