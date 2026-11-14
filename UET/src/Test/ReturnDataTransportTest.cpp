#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include "../SES/MemoryRegistry.hpp"
#include "../PDS/DefaultSemanticResponse.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::NetworkLayer;
using namespace UET::SES;

// Transport-layer fixture: implement SES's documented callbacks explicitly so
// the two directional PDS contracts can be tested before native multi-packet
// READ placement is enabled. All packets still traverse the real PDC/Fabric.
class ReturnAuditPort final : public IPacketPort {
public:
    explicit ReturnAuditPort(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        packets.push_back(packet);
        const bool data=packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header;
        const bool ack=packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header;
        if (data) {
            ++data_attempts; CHECK(frame.traffic_class==0);
            if (drop_first_data && data_attempts==1) return SendResult::Accepted;
            if (duplicate_first_data && data_attempts==1) CHECK(lower_.try_send(frame)==SendResult::Accepted);
        }
        if (ack) {
            const auto message=packet.SESpkt.bth_header.Semantic_Response_Header.message_id;
            if (message==drop_ack_message && !dropped_ack) { dropped_ack=true; return SendResult::Accepted; }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool drop_first_data=false,duplicate_first_data=false,dropped_ack=false;
    uint16_t drop_ack_message=0;
    size_t data_attempts=0;
    std::vector<PDStoNET_pkt> packets;
private:
    IPacketPort& lower_;
};

void semantic_default(PdsHost& host,const PDC_SES_req& request) {
    SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
    response.rsp_len=12; response.rsp=UET::PDS::default_semantic_response(request.pkt);
    CHECK(host.manager().pushSESResponse(response)); host.wake();
}

void inject_direction_fault(IPacketPort& port,uint32_t source,uint32_t destination,const PDStoNET_pkt& packet) {
    WireOptions network; network.source.ip.fill(0); network.destination.ip.fill(0);
    network.source.ip[3]=source; network.destination.ip[3]=destination;
    Frame frame; frame.source=source; frame.destination=destination;
    frame.bytes=UetWireCodec::encode(packet,network);
    CHECK(port.try_send(frame)==SendResult::Accepted);
}

void round_trip(pdc_mode mode,bool congestion,bool preopen,unsigned fault) {
    constexpr uint16_t read_message=42,response_message=0x3456;
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    ReturnAuditPort forward(fabric.add_host(1)),reverse(fabric.add_host(2));
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,forward),target(2,loop,trace,reverse);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,512);
        source.enable_nscc(config); target.enable_nscc(config);
    }
    MemoryRegistry source_memory,target_memory; source_memory.add_job(1); target_memory.add_job(1);
    const auto destination=source_memory.register_region(1,1,128,Access::Read|Access::Write);
    const auto remote=target_memory.register_region(1,1,128,Access::Read|Access::Write);
    std::vector<uint8_t> expected(64); for (size_t index=0;index<expected.size();++index) expected[index]=index*7+3;
    target_memory.write(1,1,remote.key,9,expected);
    size_t reads_processed=0,results_placed=0,return_completions=0,forward_completions=0;
    std::optional<PDC_SES_req> original;
    std::optional<SEStoPDS_pkt> returned;
    source.set_request_handler([&](const PDC_SES_req& request) {
        CHECK(request.PDCID<MAX_PDC && request.pkt.bth_type==Semantic_Response_with_Data_Header);
        CHECK(original && request.orig_pdcid==original->PDCID);
        const auto& header=request.pkt.bth_header.Semantic_Response_with_Data_Header;
        CHECK(header.response_message_id==response_message && header.read_request_msg_id==read_message && header.job_id==1);
        source_memory.write(1,1,destination.key,11,request.pkt.payload);
        ++results_placed; semantic_default(source,request);
    });
    target.set_request_handler([&](const PDC_SES_req& request) {
        CHECK(request.PDCID>=MAX_PDC && request.pkt.bth_type==Standard_Header);
        const auto& header=request.pkt.bth_header.Standard_Header;
        CHECK(header.opcode==2 && request.pkt.payload.empty());
        ++reads_processed; original=request;
        SEStoPDS_pkt data{}; data.bth_type=Semantic_Response_with_Data_Header;
        auto& result=data.bth_header.Semantic_Response_with_Data_Header;
        result.opcode=2; result.return_code=1; result.job_id=header.job_id;
        result.read_request_msg_id=header.msg_id; result.response_message_id=response_message;
        data.payload=target_memory.read(header.job_id,1,header.match_bits,header.buffer_offset,header.request_length);
        result.payload_length=data.payload.size(); result.modified_length=header.request_length;
        returned=data;
        // A new SES request on this PDC's return direction must be dropped
        // before it can consume that direction's first PSN or reach SES.
        PDStoNET_pkt invalid{}; invalid.PDS_type=RUOD_req_header;
        auto& wrong=invalid.PDS_header.RUOD_req_header;
        wrong.type=mode==RUD?RUD_REQ:ROD_REQ; wrong.next_hdr=UET_HDR_REQUEST_STD;
        wrong.psn=request.connection_start_psn; wrong.clear_psn_off=-1;
        wrong.spdcid=request.PDCID; wrong.dpdcid=request.orig_pdcid;
        invalid.SESpkt.bth_type=Standard_Header;
        auto& forbidden=invalid.SESpkt.bth_header.Standard_Header;
        forbidden.opcode=0; forbidden.som=forbidden.eom=1; forbidden.job_id=1;
        inject_direction_fault(reverse,2,1,invalid);
        CHECK(target.submit_return_data(request,data));
        // Delaying the forward semantic result is allowed by §3.5.20.2.2.
        // It makes return data overtake that ACK and bounds a future native
        // READ's retained work until the reverse packet has been acknowledged.
    });
    target.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(original && response.PDCID==original->PDCID && response.connection_start_psn==original->connection_start_psn);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(response.pkt.bth_type==Semantic_Response_Header && header.message_id==response_message && header.job_id==1);
        CHECK(header.return_code==1); ++return_completions;
        semantic_default(target,*original);
    });
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.PDCID<MAX_PDC && response.pkt.bth_type==Semantic_Response_Header);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(header.message_id==read_message && header.job_id==1 && header.return_code==1);
        ++forward_completions;
    });
    if (preopen) { CHECK(source.open_connection(2,1,mode)!=UINT16_MAX); loop.run(100000); }
    else {
        PDStoNET_pkt invalid{}; invalid.PDS_type=RUOD_req_header;
        auto& wrong=invalid.PDS_header.RUOD_req_header;
        wrong.type=mode==RUD?RUD_REQ:ROD_REQ; wrong.next_hdr=UET_HDR_RESPONSE_DATA;
        wrong.flags.syn=1; wrong.spdcid=99; wrong.psn=12345; wrong.clear_psn_off=-1;
        invalid.SESpkt.bth_type=Semantic_Response_with_Data_Header;
        invalid.SESpkt.bth_header.Semantic_Response_with_Data_Header.opcode=2;
        inject_direction_fault(forward,1,2,invalid); loop.run(100000);
        CHECK(target.manager().getPDSStatus().open_cnt==0 && reads_processed==0);
    }
    reverse.drop_first_data=fault==1; forward.drop_ack_message=fault==2?response_message:0;
    reverse.drop_ack_message=fault==3?read_message:0; reverse.duplicate_first_data=fault==4;
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.mode=mode;
    request.next_hdr=UET_HDR_REQUEST_STD; request.tx_pkt_handle=read_message; request.pkt_len=44;
    request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=2; header.som=header.eom=header.dc=header.rel=1;
    header.msg_id=read_message; header.job_id=1; header.PIDonFEP=header.resource_index=1; header.initiator=1;
    header.match_bits=remote.key; header.buffer_offset=9; header.request_length=expected.size();
    CHECK(source.submit(request)); loop.run(100000);
    CHECK(reads_processed==1 && results_placed==1 && return_completions==1 && forward_completions==1);
    CHECK(source_memory.read(1,1,destination.key,11,expected.size())==expected);
    CHECK(reverse.data_attempts==(fault==1||fault==2?2:1));
    uint32_t forward_sequence=0,return_sequence=0;
    for (const auto& packet:forward.packets) if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header)
        forward_sequence=packet.PDS_header.RUOD_req_header.psn;
    for (const auto& packet:reverse.packets) if (packet.PDS_type==RUOD_req_header) {
        const auto& delivery=packet.PDS_header.RUOD_req_header;
        CHECK(!delivery.flags.syn && delivery.spdcid==original->PDCID && delivery.dpdcid<MAX_PDC);
        return_sequence=delivery.psn;
    }
    CHECK(forward_sequence-return_sequence==(preopen?1u:0u));
    // A saved receive handle must not enqueue into a later incarnation, peer,
    // or an initiator context. These failures do not allocate another PDC.
    auto stale=*original; ++stale.connection_start_psn; CHECK(!target.submit_return_data(stale,*returned));
    stale=*original; ++stale.source_fep; CHECK(!target.submit_return_data(stale,*returned));
    stale=*original; stale.PDCID=1; CHECK(!target.submit_return_data(stale,*returned));
    stale=*original; stale.pkt.bth_header.Standard_Header.opcode=4;
    CHECK(!target.submit_return_data(stale,*returned)); // Fetch results must use the associated ACK.
    auto invalid_data=*returned;
    ++invalid_data.bth_header.Semantic_Response_with_Data_Header.read_request_msg_id;
    CHECK(!target.submit_return_data(*original,invalid_data));
    CHECK(std::none_of(trace.events().begin(),trace.events().end(),[](const auto& event) { return event.event=="malformed_frame"; }));
    source.close(); target.close(); CHECK(loop.pending()==0);
}

void return_data_preserves_forward_syn() {
    EventLoop loop; Services services{loop,loop,[]{}};
    I_PDC source(&services); CHECK(source.initPDC(1,1000)); source.setFep(2,1);
    PDS_PDC_req read{}; read.delivery_mode=RUD; read.next_hdr=UET_HDR_REQUEST_STD;
    read.som=read.eom=true; read.pkt.bth_type=Standard_Header;
    auto& header=read.pkt.bth_header.Standard_Header;
    header.opcode=2; header.msg_id=9; header.job_id=1; header.som=header.eom=header.dc=1; header.request_length=64;
    source.sesTxReq(&read); CHECK(source.SYN && source.state==CREATING);
    PDStoNET_pkt returned{}; returned.PDS_type=RUOD_req_header;
    auto& delivery=returned.PDS_header.RUOD_req_header;
    delivery.type=RUD_REQ; delivery.next_hdr=UET_HDR_RESPONSE_DATA;
    delivery.psn=1000; delivery.clear_psn_off=-1; delivery.spdcid=512; delivery.dpdcid=1;
    returned.SESpkt.bth_type=Semantic_Response_with_Data_Header;
    auto& data=returned.SESpkt.bth_header.Semantic_Response_with_Data_Header;
    data.opcode=2; data.return_code=1; data.job_id=1; data.read_request_msg_id=9; data.response_message_id=7;
    data.payload_length=data.modified_length=64; returned.SESpkt.payload.assign(64,3);
    source.rxReq(&returned);
    CHECK(source.SYN && source.state==CREATING && source.DPDCID==512 && source.rx_req_pkt_q.size()==1);
    SES_PDC_rsp result{}; result.rx_pkt_handle=source.rx_req_pkt_q.front().rx_pkt_handle;
    source.rx_req_pkt_q.pop(); result.rep_len=12; result.pkt=UET::PDS::default_semantic_response(returned.SESpkt);
    source.sesTxRsp(&result);
    CHECK(source.tx_pkt_q.back().PDS_header.RUOD_ack_header.dpdcid==512 && source.SYN);
    PDStoNET_pkt accepted{}; accepted.PDS_type=RUOD_ack_header;
    auto& acknowledgment=accepted.PDS_header.RUOD_ack_header;
    acknowledgment.type=ACK; acknowledgment.next_hdr=UET_HDR_RESPONSE;
    acknowledgment.cack_psn=1000; acknowledgment.spdcid=512; acknowledgment.dpdcid=1;
    accepted.SESpkt=UET::PDS::default_semantic_response(read.pkt);
    source.rxAck(&accepted); CHECK(!source.SYN && source.state==ESTABLISHED);
    source.freePDC(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true}) for (const bool preopen:{false,true})
            for (unsigned fault=0;fault<=4;++fault) round_trip(mode,congestion,preopen,fault);
        return_data_preserves_forward_syn();
        std::cout<<"PASS: same-PDC return data, independent PSNs, response token, loss/duplicates and incarnation checks\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
