#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

PDStoNET_pkt control_packet(uint32_t start,uint16_t offset,pdc_mode mode) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
    auto& header=packet.PDS_header.RUOD_cp_header;
    header.type=CP; header.ctl_type=Noop; header.flags.syn=header.flags.ar=1;
    header.flags.pdc_type=mode==ROD?1:0; header.spdcid=1; header.psn=start+offset; header.psn_off=offset;
    return packet;
}
PDStoNET_pkt data_packet(uint32_t start,uint16_t offset,pdc_mode mode) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
    auto& header=packet.PDS_header.RUOD_req_header;
    header.type=mode==ROD?ROD_REQ:RUD_REQ; header.next_hdr=UET_HDR_REQUEST_STD;
    header.flags.syn=header.flags.ar=1; header.spdcid=1; header.psn=start+offset; header.psn_off=offset;
    packet.SESpkt.bth_type=Standard_Header;
    auto& semantic=packet.SESpkt.bth_header.Standard_Header;
    semantic.opcode=0; semantic.som=semantic.eom=semantic.dc=semantic.rel=1;
    semantic.job_id=semantic.PIDonFEP=semantic.resource_index=semantic.msg_id=1;
    return packet;
}

void established_syn_range(uint32_t start,pdc_mode mode,bool control,bool beyond_range) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source=fabric.add_host(1); auto& destination=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost target_host(2,loop,trace,destination); Endpoint target(2,target_host,loop,trace);
    target.memory().add_job(1);
    std::vector<PDStoNET_pkt> responses;
    source.set_receiver([&](Frame frame) {
        responses.push_back(UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet);
    });
    const auto send=[&](const PDStoNET_pkt& packet) {
        WireOptions wire; wire.source.ip[3]=1; wire.destination.ip[3]=2;
        Frame frame; frame.source=1; frame.destination=2; frame.bytes=UetWireCodec::encode(packet,wire);
        CHECK(source.try_send(frame)==SendResult::Accepted); loop.run(100000);
    };
    send(control_packet(start,0,mode));
    CHECK(responses.size()==1 && responses.front().PDS_type==RUOD_ack_header);
    CHECK(target_host.manager().getPDSStatus().open_cnt==1); responses.clear();
    // §3.5.8.2: equality is permitted, one beyond Start_PSN+MP_RANGE is not.
    // A ROD gap may still produce ROD_OOO at the permitted SYN boundary.
    const uint16_t offset=Default_MPR+(beyond_range?1:0);
    send(control?control_packet(start,offset,mode):data_packet(start,offset,mode));
    if (responses.size()!=1)
        throw std::runtime_error("SYN response count="+std::to_string(responses.size())+
            ", start="+std::to_string(start)+", mode="+std::to_string(mode)+
            ", control="+std::to_string(control)+", beyond="+std::to_string(beyond_range));
    if (beyond_range) {
        CHECK(responses.front().PDS_type==nack_header);
        CHECK(responses.front().PDS_header.nack_header.nack_code==UET_INVALID_SYN);
        CHECK(target.retained_receive_messages()==0);
    } else if (mode==ROD) {
        CHECK(responses.front().PDS_type==nack_header &&
            responses.front().PDS_header.nack_header.nack_code==UET_ROD_OOO);
    } else CHECK(responses.front().PDS_type==RUOD_ack_header);
    CHECK(target_host.manager().getPDSStatus().open_cnt==1);
    target.close(); target_host.close(); CHECK(loop.pending()==0);
}
int main() {
    try {
        for (const uint32_t start:{1000u,UINT32_MAX-32}) for (const auto mode:{RUD,ROD})
            for (const bool control:{false,true}) for (const bool beyond:{false,true})
                established_syn_range(start,mode,control,beyond);
        std::cout<<"PASS established SYN data/control range, equality, wrap and RUD/ROD precedence\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
