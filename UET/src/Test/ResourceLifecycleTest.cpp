#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;

void pending_timeout_and_queue_bound() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,19);
    auto& port=fabric.add_host(1);
    PdsHost host(1,loop,trace,port);
    host.services().initiator_context_limit=0;
    host.services().pending_request_limit=1;
    host.services().pending_request_timeout=5*kMillisecond;
    Endpoint endpoint(1,host,loop,trace);
    endpoint.memory().add_job(1);
    Operation request; request.type=OperationType::Noop; request.peer=2;
    const auto first=endpoint.submit(request);
    loop.run_until(0);
    CHECK(host.manager().getPDSStatus().pend_cnt==1);
    const auto second=endpoint.submit(request);
    loop.run_until(0);
    Completion completion{};
    CHECK(endpoint.poll_completion(completion) && completion.operation==second);
    CHECK(completion.status==CompletionStatus::ResourceExhausted);
    loop.run_until(5*kMillisecond-1); CHECK(!endpoint.poll_completion(completion));
    loop.run_until(5*kMillisecond);
    CHECK(endpoint.poll_completion(completion) && completion.operation==first);
    CHECK(completion.status==CompletionStatus::ResourceExhausted);
    CHECK(!endpoint.poll_completion(completion) && endpoint.leased_message_ids()==0);
    CHECK(host.manager().getPDSStatus().pend_cnt==0 && loop.pending()==0);
    endpoint.submit(request); loop.run_until(loop.now());
    endpoint.close(); host.close();
    CHECK(loop.pending()==0); // A queued request's deadline cannot outlive its host.
}

void reclaim_idle_context_and_resume() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,20);
    auto& first_port=fabric.add_host(1);
    auto& second_port=fabric.add_host(2);
    auto& third_port=fabric.add_host(3);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    fabric.add_link(1,3,{}); fabric.add_link(3,1,{});
    PdsHost first_host(1,loop,trace,first_port),second_host(2,loop,trace,second_port),third_host(3,loop,trace,third_port);
    first_host.services().initiator_context_limit=1;
    first_host.services().target_context_limit=1;
    Endpoint first(1,first_host,loop,trace),second(2,second_host,loop,trace),third(3,third_host,loop,trace);
    first.memory().add_job(1); second.memory().add_job(1); third.memory().add_job(1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2;
    first.submit(noop); loop.run_until(kMillisecond);
    Completion completion{};
    CHECK(first.poll_completion(completion) && completion.status==CompletionStatus::Success);
    // The reverse direction consumes a target ID, independent of the full
    // initiator pool. A shared open-count limit would incorrectly reject it.
    noop.peer=1; second.submit(noop); loop.run_until(2*kMillisecond);
    CHECK(second.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(first_host.manager().getPDSStatus().open_cnt==2);
    noop.peer=3; first.submit(noop); loop.run_until(3*kMillisecond);
    CHECK(first.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(first_host.manager().getPDSStatus().pend_cnt==0);
    CHECK(first_host.manager().getPDSStatus().open_cnt==2);
    first.close(); second.close(); third.close();
    first_host.close(); second_host.close(); third_host.close();
    CHECK(loop.pending()==0);
}

class ResourceNackProbe : public IPacketPort {
public:
    ResourceNackProbe(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        if (decoded.packet.PDS_type==RUOD_req_header) request_times.push_back(loop_.now());
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override {
        lower_.set_receiver([this,receiver=std::move(receiver)](Frame frame) {
            const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
            if (packet.PDS_type==nack_header && !packet.PDS_header.nack_header.spdcid) nack_times.push_back(loop_.now());
            if (receiver) receiver(std::move(frame));
        });
    }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    std::vector<Time> request_times,nack_times;
private:
    IPacketPort& lower_;
    EventLoop& loop_;
};

void resource_nack_pause_and_recovery() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,21);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    ResourceNackProbe probe(forward,loop);
    PdsHost source_host(1,loop,trace,probe),target_host(2,loop,trace,reverse);
    source_host.services().nack_retransmission_delays_ns[1]=4*kMillisecond;
    target_host.services().target_context_limit=0;
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2;
    source.submit(noop); loop.run_until(3*kMillisecond);
    CHECK(probe.request_times.size()==1 && probe.nack_times.size()==1);
    target_host.services().target_context_limit=1;
    loop.run_until(5*kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(probe.request_times.size()==2 && probe.request_times[1]>=probe.nack_times[0]+4*kMillisecond);
    CHECK(!source.poll_completion(completion));
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(loop.pending()==0);
}

void fatal_target_close_is_bounded() {
    EventLoop loop; Services services{loop,loop,[]{}};
    ThreadSafeQueue<uint16_t> closed;
    T_PDC target(&services); CHECK(target.initPDC(MAX_PDC));
    target.setPublicQueues(nullptr,nullptr,nullptr,&closed);
    target.state=ESTABLISHED; target.close_error=true;
    target.openChk();
    uint16_t identifier=0;
    CHECK(target.state==CLOSED && closed.pop(identifier) && identifier==MAX_PDC);
    CHECK(!target.hasPendingWork() && loop.pending()==0);
    I_PDC initiator(&services); CHECK(initiator.initPDC(1));
    initiator.setPublicQueues(nullptr,nullptr,nullptr,&closed);
    initiator.state=ESTABLISHED; initiator.open_msg=1; initiator.close_error=true;
    initiator.openChk();
    CHECK(initiator.state==CLOSED && closed.pop(identifier) && identifier==1);
    CHECK(!initiator.hasPendingWork() && loop.pending()==0);
}

int main() {
    try {
        pending_timeout_and_queue_bound();
        reclaim_idle_context_and_resume();
        resource_nack_pause_and_recovery();
        fatal_target_close_is_bounded();
        std::cout<<"PASS: bounded pending requests, independent PDC pools, idle reclamation and NACK backoff\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
