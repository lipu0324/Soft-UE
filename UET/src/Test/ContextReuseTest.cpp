#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

class CapturedContextPort : public IPacketPort {
public:
    CapturedContextPort(IPacketPort& lower,EventLoop& loop,bool drop_first=false)
        : lower_(lower),loop_(loop),drop_first_(drop_first) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header) {
            const auto& header=packet.PDS_header.RUOD_req_header;
            local_pdc=header.spdcid;
            if (requests++==0) first_request=frame;
            request_sequences.push_back(header.psn);
            if (header.flags.syn && !header.flags.retx && drop_first_) {
                drop_first_=false; return SendResult::Accepted;
            }
        } else if (packet.PDS_type==RUOD_ack_header &&
                   packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE && !first_response)
            first_response=frame;
        else if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Close_cmd) {
            close_times.push_back(loop_.now());
            close_sequences.push_back(packet.PDS_header.RUOD_cp_header.psn);
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    uint16_t local_pdc=UINT16_MAX;
    size_t requests=0;
    std::optional<Frame> first_request,first_response;
    std::vector<uint32_t> request_sequences;
    std::vector<Time> close_times;
    std::vector<uint32_t> close_sequences;
private:
    IPacketPort& lower_;
    EventLoop& loop_;
    bool drop_first_;
};

void context_reuse_and_late_packets() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    CapturedContextPort source_port(forward,loop),target_port(reverse,loop);
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto counter=target.memory().register_region(1,1,8,7);
    Operation increment; increment.type=OperationType::Atomic; increment.peer=2;
    increment.remote_key=counter.key; increment.payload={1,0,0,0,0,0,0,0};
    source.submit(increment); loop.run_until(kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    const auto first_pdc=source_port.local_pdc;
    CHECK(source_host.request_connection_close(first_pdc));
    source.submit(increment); // Queued while the first ordered context is quiescing.
    loop.run_until(2*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(source_port.local_pdc==first_pdc);
    CHECK(source_port.request_sequences.size()==2 && source_port.close_sequences.size()==1);
    const uint32_t epoch_separation=source_port.request_sequences[1]-source_port.close_sequences.front();
    CHECK(epoch_separation>=65536 && epoch_separation<0x80000000u);
    CHECK(source_host.manager().getPDSStatus().open_cnt==1);
    CHECK(target_host.manager().getPDSStatus().open_cnt==1);

    CHECK(source_port.first_request && target_port.first_response);
    CHECK(forward.try_send(*source_port.first_request)==SendResult::Accepted);
    CHECK(reverse.try_send(*target_port.first_response)==SendResult::Accepted);
    source.submit(increment);
    loop.run_until(3*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion));
    CHECK(target.memory().read(1,1,counter.key,0,8)==std::vector<uint8_t>({3,0,0,0,0,0,0,0}));
    CHECK(target.retained_receive_messages()==0 && source.leased_message_ids()==0);
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(loop.pending()==0);
}

void lost_syn_safety(bool close_before_deadline) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    CapturedContextPort source_port(forward,loop,true);
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2;
    source.submit(noop); loop.run_until(2*kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(source_host.request_connection_close(source_port.local_pdc));
    loop.run_until(3*kMillisecond);
    CHECK(source_port.close_times.empty());
    if (!close_before_deadline) {
        loop.run_until(64*kMillisecond); CHECK(source_port.close_times.empty());
        loop.run_until(66*kMillisecond);
        CHECK(source_port.close_times.size()==1 && source_port.close_times[0]>=65*kMillisecond);
        CHECK(source_host.manager().getPDSStatus().open_cnt==0);
        CHECK(target_host.manager().getPDSStatus().open_cnt==0);
    }
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(loop.pending()==0); // Closing the host invalidates a pending safety wake.
}

int main() {
    try {
        context_reuse_and_late_packets();
        lost_syn_safety(false);
        lost_syn_safety(true);
        std::cout<<"PASS: PDC reuse, queued messages, late old packets and SYN safety/cancellation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
