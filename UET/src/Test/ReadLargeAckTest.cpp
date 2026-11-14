#include "Check.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::NetworkLayer;
using namespace UET::SES;

// Independently observe the chosen carrier and READ's empty request payload.
// The loss injector can discard the first or final ACK-data fragment, not an
// arbitrary DEFAULT whose semantics could legally be inferred from CACK.
class LargeAckAuditPort final : public IPacketPort {
public:
    explicit LargeAckAuditPort(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (observe) observe();
        if (packet.PDS_type==RUOD_req_header) {
            CHECK(packet.SESpkt.bth_type==Standard_Header); // No reverse PDS data in this fabric branch.
            const auto& request=packet.SESpkt.bth_header.Standard_Header;
            if (request.opcode==2) {
                CHECK(packet.SESpkt.payload.empty() && (request.som || !request.diff.som_false.payload_length));
                ++read_attempts;
                if (drop_first_read && read_attempts==1) return SendResult::Accepted;
            }
        }
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==ACK_req) ++queries;
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header) {
            const auto& data=packet.SESpkt.bth_header.Semantic_Response_with_Data_Header;
            CHECK(data.opcode==2 && data.return_code==1 && data.modified_length==total &&
                data.payload_length==std::min<uint32_t>(1024,total-data.message_offset));
            CHECK((packet.PDS_header.RUOD_ack_header.flags.req&1) && frame.traffic_class==1);
            ++data_ack_attempts;
            const bool selected=lose_final?data.message_offset+data.payload_length==total:data.message_offset==0;
            if (lose_ack && selected && !dropped_ack) {
                dropped_ack=true;
                if (on_drop) on_drop(data.message_offset,data.payload_length);
                return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    uint32_t total=0;
    bool drop_first_read=false,lose_ack=false,lose_final=false,dropped_ack=false;
    size_t read_attempts=0,data_ack_attempts=0,queries=0;
    std::function<void(uint32_t,uint32_t)> on_drop;
    std::function<void()> observe;
private:
    IPacketPort& lower_;
};

void fragmented_ack_data(pdc_mode mode,bool congestion,uint32_t threshold,uint32_t length,unsigned fault) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    LargeAckAuditPort forward(fabric.add_host(1)),reverse(fabric.add_host(2));
    forward.total=reverse.total=length;
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(threshold); target_host.configure_read_ack_data(threshold);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1132);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto destination=source.memory().register_region(1,1,uint64_t{length}+64,Access::Read|Access::Write);
    const auto remote=target.memory().register_region(1,1,uint64_t{length}+64,Access::Read|Access::Write);
    std::vector<uint8_t> expected(length); for (size_t index=0;index<expected.size();++index) expected[index]=index*17+3;
    target.memory().write(1,1,remote.key,7,expected);
    forward.drop_first_read=fault==1; reverse.lose_ack=fault>=2; reverse.lose_final=fault==3;
    reverse.on_drop=[&](uint32_t offset,uint32_t count) {
        for (uint32_t index=offset;index<offset+count;++index) expected[index]^=0x5a;
        target.memory().write(1,1,remote.key,7+offset,std::vector<uint8_t>(expected.begin()+offset,expected.begin()+offset+count));
    };
    const auto observe=[&] {
        CHECK(source.pending_read_results()<=8 && target.retained_read_packets()<=8 && target.pending_read_returns()==0);
    };
    forward.observe=reverse.observe=observe;
    Operation read; read.type=OperationType::Read; read.peer=2; read.delivery_mode=mode;
    read.remote_key=remote.key; read.remote_offset=7; read.read_length=length;
    read.read_result=ReadResultBuffer{destination.key,11,length,1,1};
    const auto operation=source.submit(read);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2; noop.delivery_mode=mode;
    const auto following=source.submit(noop); loop.run(1000000);
    Completion completion{}; size_t reads=0,noops=0;
    while (source.poll_completion(completion)) {
        if (completion.operation==operation) { ++reads; CHECK(completion.status==CompletionStatus::Success && completion.length==length); }
        else { CHECK(completion.operation==following && completion.status==CompletionStatus::Success); ++noops; }
    }
    CHECK(reads==1 && noops==1 && !target.poll_completion(completion));
    CHECK(source.memory().read(1,1,destination.key,11,length)==expected);
    CHECK(forward.queries==0 && target.retained_read_packets()==0 && target.retained_receive_messages()==0 && source.leased_message_ids()==0);
    CHECK(reverse.dropped_ack==(fault>=2) && reverse.data_ack_attempts>=((uint64_t{length}+1023)/1024)+(fault>=2?1:0));
    source_host.configure_semantic_payload_mtu(1024); // Same configuration may attach to a live PDC.
    check_throws<std::logic_error>([&] { source_host.configure_semantic_payload_mtu(512); });
    CHECK(source.capabilities().max_read_length==UINT32_MAX && !source.capabilities().hpc);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

class ReadSourceSnapshot : public I_PDC {
public:
    using I_PDC::I_PDC;
    using PDC::requiresReadReissue;
};
void response_policy_snapshot() {
    EventLoop loop; Services services{loop,loop,[]{}};
    services.max_ack_data_size=1024; services.semantic_payload_mtu=1024;
    ReadSourceSnapshot source(&services); CHECK(source.initPDC(1,1000)); source.setFep(2,1);
    PDS_PDC_req request{}; request.delivery_mode=RUD; request.next_hdr=UET_HDR_REQUEST_STD;
    request.som=true; request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=2; header.som=1; header.msg_id=9; header.job_id=1; header.request_length=4099;
    source.sesTxReq(&request); CHECK(source.requiresReadReissue(1000));
    services.max_ack_data_size=16; services.semantic_payload_mtu=8192;
    CHECK(source.requiresReadReissue(1000)); // Policy belongs to the existing incarnation.
    PDStoNET_pkt response{}; response.PDS_type=RUOD_ack_header;
    auto& acknowledgment=response.PDS_header.RUOD_ack_header;
    acknowledgment.type=ACK; acknowledgment.next_hdr=UET_HDR_RESPONSE_DATA;
    acknowledgment.cack_psn=999; acknowledgment.ack_psn_off=1; acknowledgment.spdcid=512; acknowledgment.dpdcid=1;
    response.SESpkt.bth_type=Semantic_Response_with_Data_Header;
    auto& data=response.SESpkt.bth_header.Semantic_Response_with_Data_Header;
    data.opcode=2; data.return_code=1; data.job_id=1; data.read_request_msg_id=9;
    data.modified_length=4099; data.payload_length=1024; response.SESpkt.payload.assign(1024,3);
    source.rxAck(&response); CHECK(source.rx_rsp_pkt_q.size()==1 && source.tx_pkt_buffer.empty());
    source.freePDC(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true})
            for (const uint32_t threshold:{1024,8192}) for (unsigned fault=0;fault<=3;++fault)
                fragmented_ack_data(mode,congestion,threshold,fault==1?2051:32771,fault);
        response_policy_snapshot();
        std::cout<<"PASS: multi-packet READ in data ACKs, per-fragment offsets, empty requests, lost ACK re-execution and policy snapshot\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
