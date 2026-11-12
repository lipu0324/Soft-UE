#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

// Faults operate on real encoded packets. The transport reports acceptance
// even when the network drops a frame, exactly as an Ethernet port would.
class RecoveryFaultPort : public IPacketPort {
public:
    RecoveryFaultPort(IPacketPort& downstream, bool drop_second_request, bool duplicate_requests)
        : downstream_(downstream), drop_second_request_(drop_second_request),
          duplicate_requests_(duplicate_requests) {}
    SendResult try_send(const Frame& frame) override {
        const auto decoded = UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        if (decoded.packet.PDS_type == nack_header) {
            ++negative_ack_count;
            negative_ack_codes.push_back(decoded.packet.PDS_header.nack_header.nack_code);
        }
        if (decoded.packet.PDS_type == RUOD_req_header) {
            ++request_count;
            if (decoded.packet.PDS_header.RUOD_req_header.flags.retx) ++retransmit_count;
            if (drop_second_request_ && request_count == 2) return SendResult::Accepted;
            const auto accepted = downstream_.try_send(frame);
            if (duplicate_requests_ && accepted == SendResult::Accepted)
                CHECK(downstream_.try_send(frame) == SendResult::Accepted);
            return accepted;
        }
        return downstream_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { downstream_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { downstream_.set_writable_handler(std::move(callback)); }
    size_t request_count=0, retransmit_count=0, negative_ack_count=0;
    std::vector<PDS_Nack_Codes> negative_ack_codes;
private:
    IPacketPort& downstream_;
    bool drop_second_request_, duplicate_requests_;
};

void recover_missing_middle_packet(bool duplicate_requests, pdc_mode delivery_mode,size_t payload_size=64) {
    EventLoop event_loop;
    Trace trace(event_loop);
    Fabric fabric(event_loop,trace,42);
    auto& source_port = fabric.add_host(1);
    auto& target_port = fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    RecoveryFaultPort source_faults(source_port,true,duplicate_requests);
    RecoveryFaultPort target_faults(target_port,false,false);
    PdsHost source_host(1,event_loop,trace,source_faults);
    PdsHost target_host(2,event_loop,trace,target_faults);
    Endpoint source(1,source_host,event_loop,trace,16);
    Endpoint target(2,target_host,event_loop,trace,16);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto destination = target.memory().register_region(1,1,4096,7);
    Operation write;
    write.type=OperationType::Write; write.peer=2; write.remote_key=destination.key;
    write.delivery_mode=delivery_mode;
    for (size_t value=0;value<payload_size;++value) write.payload.push_back(static_cast<uint8_t>(value));
    source.submit(write);

    // The PDC RTO is 1 ms. Success before 0.5 ms proves the NACK reached the
    // source and triggered go-back-N rather than being hidden by a timer.
    event_loop.run_until(delivery_mode==ROD?kMillisecond/2:3*kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion));
    CHECK(completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion));
    CHECK(target.memory().read(1,1,destination.key,0,payload_size)==write.payload);
    if (delivery_mode==ROD) CHECK(target_faults.negative_ack_count>0);
    else {
        // RUD accepts out-of-order data. An ACK Request may still elicit a
        // PKT_NOT_RCVD NACK for the hole when the larger window fills.
        CHECK(std::find(target_faults.negative_ack_codes.begin(),target_faults.negative_ack_codes.end(),UET_ROD_OOO)==
            target_faults.negative_ack_codes.end());
        std::vector<uint64_t> delivered_sequences;
        for (const auto& event:trace.events())
            if (event.node==2 && event.event=="ses_request") delivered_sequences.push_back(event.value);
        if (payload_size==64) CHECK(delivered_sequences==std::vector<uint64_t>({1000,1002,1003,1001}));
        else CHECK(std::find(delivered_sequences.begin(),delivered_sequences.end(),1002)<
                   std::find(delivered_sequences.begin(),delivered_sequences.end(),1001));
    }
    CHECK(source_faults.retransmit_count>0);
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(event_loop.pending()==0);
}

void reject_wrong_connection_identity() {
    EventLoop event_loop;
    Services services{event_loop,event_loop,[]{}};
    PDS_Manager manager(&services);
    CHECK(manager.initPDSM());
    CHECK(manager.allocPDC(MAX_PDC,1,2));
    PDStoNET_pkt request{};
    request.src_fep=3; request.dst_fep=2; request.PDS_type=RUOD_req_header;
    auto& header=request.PDS_header.RUOD_req_header;
    header.type=ROD_REQ; header.next_hdr=UET_HDR_NONE;
    header.dpdcid=MAX_PDC; header.spdcid=7; header.psn=42;
    CHECK(manager.Net_rx_pkt_q.push(request)); manager.mainChk();
    PDStoNET_pkt rejection{};
    CHECK(manager.PDStoNet.pop(rejection));
    CHECK(rejection.PDS_header.nack_header.nack_code==UET_PDC_HDR_MISMATCH);
    CHECK(rejection.PDS_header.nack_header.nack_psn==42);
    CHECK(rejection.PDS_header.nack_header.dpdcid==7);
    CHECK(manager.PDStoNet.empty());

    // A late close CP to an unknown destination gets one INV_DPDCID NACK.
    // The same packet's flags must be read through its CP header, not RUOD.
    request.PDS_type=RUOD_cp_header; request.PDS_header={};
    auto& control=request.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=Close_cmd; control.dpdcid=UINT16_MAX;
    control.spdcid=9; control.psn=1234;
    CHECK(manager.Net_rx_pkt_q.push(request)); manager.mainChk();
    CHECK(manager.PDStoNet.pop(rejection));
    CHECK(rejection.PDS_header.nack_header.nack_code==UET_INV_DPDCID);
    CHECK(rejection.PDS_header.nack_header.nack_psn==1234);
    CHECK(rejection.PDS_header.nack_header.dpdcid==9);
    CHECK(manager.PDStoNet.empty());
}

int main() {
    try {
        recover_missing_middle_packet(false,ROD);
        recover_missing_middle_packet(true,ROD);
        recover_missing_middle_packet(false,RUD);
        recover_missing_middle_packet(true,RUD);
        recover_missing_middle_packet(false,ROD,512);
        recover_missing_middle_packet(false,RUD,512);
        reject_wrong_connection_identity();
        std::cout << "PASS: NACK-driven go-back-N, duplicate suppression and connection identity checks\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
