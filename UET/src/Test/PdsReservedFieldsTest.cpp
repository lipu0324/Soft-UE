#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include "../Network_Layer/PdsPacketCodec.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

void repair_crc(std::vector<uint8_t>& bytes,const WireOptions& network) {
    if (!network.crc) return;
    const size_t start=14+(network.ipv6?8:12),end=bytes.size()-4;
    const auto checksum=UetWireCodec::crc32c(bytes.data()+start,end-start);
    for (size_t index=0;index<4;++index) bytes[end+index]=checksum>>(24-8*index);
}
std::vector<PDStoNET_pkt> packets() {
    std::vector<PDStoNET_pkt> result;
    for (const auto type:{RUD_REQ,ROD_REQ}) {
        PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
        auto& header=packet.PDS_header.RUOD_req_header;
        header.type=type; header.next_hdr=UET_HDR_REQUEST_STD; header.flags.syn=header.flags.ar=1;
        header.psn=1000; header.spdcid=7; header.pdc_info=1;
        packet.SESpkt.bth_type=Standard_Header;
        auto& semantic=packet.SESpkt.bth_header.Standard_Header;
        semantic.som=semantic.eom=semantic.dc=1; semantic.job_id=1;
        semantic.PIDonFEP=semantic.resource_index=1; semantic.msg_id=3;
        result.push_back(packet);
    }
    for (const auto type:{ACK,ACK_CC}) {
        PDStoNET_pkt packet{}; packet.PDS_type=RUOD_ack_header;
        auto& header=packet.PDS_header.RUOD_ack_header;
        header.type=type; header.next_hdr=UET_HDR_NONE; header.cack_psn=1000; header.spdcid=512; header.dpdcid=7;
        result.push_back(packet);
    }
    PDStoNET_pkt negative{}; negative.PDS_type=nack_header;
    auto& nack=negative.PDS_header.nack_header;
    nack.type=NACK; nack.next_hdr=UET_HDR_NONE; nack.nack_code=UET_TRIMMED;
    nack.nack_psn=nack.payload=1000; nack.spdcid=512; nack.dpdcid=7; result.push_back(negative);
    for (const auto type:{Noop,Negotiation,Probe}) {
        PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
        auto& header=packet.PDS_header.RUOD_cp_header;
        header.type=CP; header.ctl_type=type; header.spdcid=7; header.psn=1000; header.flags.ar=1;
        if (type!=Probe) { header.flags.pdc_type=1; header.flags.syn=1; header.pdc_info=1; }
        else header.dpdcid=512;
        if (type==Negotiation) packet.control_extension.assign(28,0);
        result.push_back(packet);
    }
    auto control_ack=result.at(2); control_ack.PDS_header.RUOD_ack_header.next_hdr=UET_HDR_CP_ACK;
    control_ack.control_ack.cp_ack_type=Close_cmd; control_ack.control_ack.cp_ack_length=2;
    control_ack.control_ack.expected_psn=1001; result.push_back(control_ack);
    auto datagram=result.front(); datagram.PDS_type=UUD_req_header; datagram.PDS_header={};
    datagram.PDS_header.UUD_req_header.type=UUD_REQ; datagram.PDS_header.UUD_req_header.next_hdr=UET_HDR_REQUEST_STD;
    datagram.SESpkt.bth_header.Standard_Header.opcode=7; datagram.SESpkt.bth_header.Standard_Header.msg_id=0;
    datagram.SESpkt.bth_header.Standard_Header.dc=0; result.push_back(datagram);
    return result;
}
void reserved_fields() {
    for (const bool ipv6:{false,true}) for (const bool udp:{false,true}) for (const bool crc:{false,true}) {
        WireOptions network; network.ipv6=ipv6; network.udp=udp; network.crc=crc;
        const size_t pds=14+(ipv6?40:20)+(udp?8:4);
        for (const auto& packet:packets()) {
            const auto canonical=UetWireCodec::encode(packet,network); auto changed=canonical;
            if (!udp) changed[pds-2]=changed[pds-1]=0xff;
            if (packet.PDS_type==RUOD_req_header) {
                changed[pds+1]|=0x63; changed[pds+10]|=0xe0;
                auto local=packet; local.PDS_header.RUOD_req_header.pdc_info|=0xe;
                CHECK(UetWireCodec::encode(local,network)==canonical);
            } else if (packet.PDS_type==RUOD_ack_header) {
                changed[pds+1]|=0x41;
                if (packet.PDS_header.RUOD_ack_header.type==ACK_CC) changed[pds+12]|=0xf;
                if (packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_CP_ACK) changed[pds+15]=0xff;
            } else if (packet.PDS_type==nack_header) changed[pds+1]|=0x47;
            else if (packet.PDS_type==RUOD_cp_header) {
                changed[pds+1]|=3;
                if (packet.PDS_header.RUOD_cp_header.ctl_type==Probe) changed[pds+1]|=0x60;
                else changed[pds+10]|=0xe0;
            } else {
                changed[pds+1]|=0x7f; changed[pds+2]=changed[pds+3]=0xff;
            }
            if (crc) check_throws<std::invalid_argument>([&] { UetWireCodec::decode(changed.data(),changed.size(),true); });
            repair_crc(changed,network);
            const auto decoded=UetWireCodec::decode(changed.data(),changed.size(),crc).packet;
            CHECK(UetWireCodec::encode(decoded,network)==canonical);
        }
    }
    // pdc_type is a two-bit field, not a reserved flag. The generic CP codec
    // preserves its value; the current context manager enables only 00/01.
    auto control=packets().at(5);
    for (uint8_t type=0;type<4;++type) {
        control.PDS_header.RUOD_cp_header.flags.pdc_type=type;
        const auto wire=UetWireCodec::encode(control,{});
        CHECK(UetWireCodec::decode(wire.data(),wire.size()).packet.PDS_header.RUOD_cp_header.flags.pdc_type==type);
        if (type<2) {
            const auto legacy=PdsPacketCodec::encode(control);
            CHECK(PdsPacketCodec::decode(legacy.data(),legacy.size()).PDS_header.RUOD_cp_header.flags.pdc_type==type);
        }
    }
    control.PDS_header.RUOD_cp_header.flags.pdc_type=2;
    check_throws<std::invalid_argument>([&] { PdsPacketCodec::encode(control); });
}
void reserved_ack_request_cannot_bind_peer() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost host(1,loop,trace,forward); Endpoint source(1,host,loop,trace); source.memory().add_job(1);
    PDStoNET_pkt original{};
    fabric.set_capture([&](Time,const Frame& frame) {
        if (frame.source==1) {
            const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
            if (packet.PDS_type==RUOD_req_header) original=packet;
        }
    });
    Operation operation; operation.type=OperationType::Noop; operation.peer=2; source.submit(operation); loop.run_until(0);
    const auto& request=original.PDS_header.RUOD_req_header;
    PDStoNET_pkt response{}; response.PDS_type=RUOD_ack_header;
    auto& ack=response.PDS_header.RUOD_ack_header;
    ack.type=ACK; ack.next_hdr=UET_HDR_RESPONSE; ack.cack_psn=request.psn; ack.dpdcid=request.spdcid;
    ack.spdcid=900; ack.flags.req=3;
    response.SESpkt.bth_type=Semantic_Response_Header;
    auto& semantic=response.SESpkt.bth_header.Semantic_Response_Header;
    semantic.return_code=1; semantic.job_id=1; semantic.message_id=original.SESpkt.bth_header.Standard_Header.msg_id;
    WireOptions wire; wire.source.ip[3]=2; wire.destination.ip[3]=1;
    Frame frame; frame.source=2; frame.destination=1; frame.bytes=UetWireCodec::encode(response,wire);
    CHECK(reverse.try_send(frame)==SendResult::Accepted); loop.run_until(5000);
    Completion completion{}; CHECK(!source.poll_completion(completion) && host.manager().getPDSStatus().event_cnt==1);
    ack.spdcid=512; ack.flags.req=0; frame.bytes=UetWireCodec::encode(response,wire);
    CHECK(reverse.try_send(frame)==SendResult::Accepted); loop.run_until(10000);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    source.close(); host.close(); CHECK(loop.pending()==0);
}
void unsupported_control_modes_do_not_allocate() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source=fabric.add_host(1); auto& destination=fabric.add_host(2); fabric.add_link(1,2,{});
    PdsHost target(2,loop,trace,destination); auto control=packets().at(5);
    WireOptions network; network.source.ip[3]=1; network.destination.ip[3]=2;
    for (uint8_t type=2;type<4;++type) {
        control.PDS_header.RUOD_cp_header.flags.pdc_type=type;
        Frame frame; frame.source=1; frame.destination=2; frame.bytes=UetWireCodec::encode(control,network);
        CHECK(source.try_send(frame)==SendResult::Accepted); loop.run();
        CHECK(target.manager().getPDSStatus().open_cnt==0);
    }
    CHECK(target.manager().getPDSStatus().event_cnt==2); target.close(); CHECK(loop.pending()==0);
}
int main() {
    try {
        reserved_fields(); reserved_ack_request_cannot_bind_peer(); unsupported_control_modes_do_not_allocate();
        std::cout<<"PASS PDS reserved fields, CRC, full CP type, reserved ACK request and peer-state isolation\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
