#include "Check.hpp"
#include "../Runtime/PdsHost.hpp"
#include "../SES/Endpoint.hpp"
#include <deque>
#include <iostream>
#include <type_traits>

using namespace UET::Runtime;
using namespace UET::SES;
static_assert(!std::is_copy_constructible<RealtimeRuntime>::value && !std::is_move_constructible<RealtimeRuntime>::value,
    "self-bound realtime clocks require stable runtime ownership");

class ManualElapsedClock final : public IClock {
public:
    Time now() const override { return elapsed; }
    Time elapsed=0;
};

void late_timer_restart() {
    ManualElapsedClock clock; RealtimeRuntime runtime(clock);
    size_t firings=0; TimerId scheduled=0; std::function<void()> retry;
    retry=[&] { ++firings; scheduled=runtime.events().after(kMillisecond,retry); };
    scheduled=runtime.events().after(kMillisecond,retry);
    clock.elapsed=10*kMillisecond; runtime.progress();
    if (firings!=1) std::cerr<<"late progress fired retry="<<firings<<" times in one present-time snapshot\n";
    CHECK(firings==1 && runtime.events().now()==clock.elapsed);
    runtime.progress(); CHECK(firings==1);
    clock.elapsed=11*kMillisecond; runtime.progress(); CHECK(firings==2);
    CHECK(runtime.events().cancel(scheduled) && runtime.events().pending()==0);
    check_throws<std::invalid_argument>([&] { runtime.events().run_until(clock.elapsed+1); });
    runtime.events().after(kMillisecond,[&] {
        CHECK(runtime.events().now()==20*kMillisecond);
        clock.elapsed+=3*kMillisecond; // Deterministically model work during the callback.
        CHECK(runtime.events().now()==23*kMillisecond);
        scheduled=runtime.events().after(kMillisecond,[&] { ++firings; });
    });
    clock.elapsed=20*kMillisecond; runtime.progress(); CHECK(firings==2);
    runtime.progress(); CHECK(firings==2);
    clock.elapsed=24*kMillisecond; runtime.progress(); CHECK(firings==3);
    // Absolute overdue deadlines are valid for live timers; virtual at(past)
    // remains an error in runtime_test. Neither mode may rewind its clock.
    runtime.events().at(0,[&] { ++firings; }); runtime.progress(); CHECK(firings==4);
    clock.elapsed=23*kMillisecond;
    check_throws<std::invalid_argument>([&] { runtime.progress(); });
}

// A manual-progress network adapter. It only queues unchanged frames until
// flush(); it does not ACK, retransmit, reorder or access either peer's MR.
class DeferredFramePort final : public IPacketPort {
public:
    DeferredFramePort(uint32_t node,const IClock& actual_time):node_(node),actual_time_(actual_time) {}
    SendResult try_send(const Frame& frame) override {
        if (!peer || frame.source!=node_ || frame.destination!=peer->node_) return SendResult::NoRoute;
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            packet.SESpkt.bth_header.Standard_Header.opcode==1) write_departures.push_back(actual_time_.now());
        peer->incoming_.push_back(frame); return SendResult::Accepted;
    }
    void set_receiver(Receiver receiver) override { receiver_=std::move(receiver); }
    void set_writable_handler(Writable) override {}
    void flush() {
        while (!incoming_.empty()) {
            auto frame=std::move(incoming_.front()); incoming_.pop_front();
            if (receiver_) receiver_(std::move(frame));
        }
    }
    DeferredFramePort* peer=nullptr;
    std::vector<Time> write_departures;
private:
    uint32_t node_;
    const IClock& actual_time_;
    Receiver receiver_;
    std::deque<Frame> incoming_;
};

void late_pds_progress() {
    ManualElapsedClock clock; RealtimeRuntime source_runtime(clock),target_runtime(clock);
    auto& source_loop=source_runtime.events(); auto& target_loop=target_runtime.events();
    Trace source_trace(source_loop),target_trace(target_loop);
    DeferredFramePort source_port(1,clock),target_port(2,clock); source_port.peer=&target_port; target_port.peer=&source_port;
    PdsHost source_host(1,source_loop,source_trace,source_port),target_host(2,target_loop,target_trace,target_port);
    source_host.services().rto_ns=kMillisecond; target_host.services().rto_ns=kMillisecond;
    Endpoint source(1,source_host,source_loop,source_trace,1024,5000*kMillisecond);
    Endpoint target(2,target_host,target_loop,target_trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto remote=target.memory().register_region(1,1,8,Access::Read|Access::Write);
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=remote.key; write.payload={0x5a};
    const auto operation=source.submit(write); source_runtime.progress();
    CHECK(source_port.write_departures==std::vector<Time>({0}));
    // Delay all application progress for one second. The actual retransmission
    // happens now, so its next RTO cannot also expire in this same call.
    clock.elapsed=1000*kMillisecond; source_runtime.progress();
    if (source_port.write_departures.size()!=2)
        std::cerr<<"late PDS progress transmitted "<<source_port.write_departures.size()<<" requests before the peer could progress\n";
    CHECK(source_port.write_departures==std::vector<Time>({0,clock.elapsed}));
    Completion completion{}; CHECK(!source.poll_completion(completion));
    target_port.flush(); target_runtime.progress(); source_port.flush(); source_runtime.progress();
    CHECK(source.poll_completion(completion) && completion.operation==operation && completion.status==CompletionStatus::Success);
    CHECK(target.memory().read(1,1,remote.key,0,1)==std::vector<uint8_t>({0x5a}));
    for (unsigned step=0;step<10;++step) {
        clock.elapsed+=kMillisecond;
        source_port.flush(); source_runtime.progress(); target_port.flush(); target_runtime.progress();
    }
    CHECK(source.leased_message_ids()==0 && target.retained_receive_messages()==0);
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(source_loop.pending()==0 && target_loop.pending()==0);
}

int main(int argc,char** argv) {
    try {
        if (argc==2 && std::string(argv[1])=="--pds-only") late_pds_progress();
        else { CHECK(argc==1); late_timer_restart(); late_pds_progress(); }
        std::cout<<"PASS late realtime progress restarts timers from actual dispatch and preserves PDS recovery\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
