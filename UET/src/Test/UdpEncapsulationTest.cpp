#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::NetworkLayer;

PDStoNET_pkt noop_control() {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
    auto& control=packet.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=Noop; control.flags.syn=control.flags.ar=1;
    control.flags.pdc_type=1; control.spdcid=7; control.psn=1000;
    return packet;
}
PDStoNET_pkt semantic_noop() {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
    auto& request=packet.PDS_header.RUOD_req_header;
    request.type=ROD_REQ; request.next_hdr=UET_HDR_REQUEST_STD;
    request.flags.syn=request.flags.ar=1; request.spdcid=7; request.psn=1000;
    packet.SESpkt.bth_type=Standard_Header;
    auto& semantic=packet.SESpkt.bth_header.Standard_Header;
    semantic.opcode=0; semantic.som=semantic.eom=semantic.dc=semantic.rel=1;
    semantic.job_id=semantic.PIDonFEP=semantic.resource_index=semantic.msg_id=1;
    return packet;
}
void configurable_wire_port() {
    for (const bool ipv6:{false,true}) for (const bool crc:{false,true})
        for (const uint16_t destination:{0,4793,49150,65535}) {
        WireOptions network; network.ipv6=ipv6; network.udp=true; network.crc=crc;
        network.udp_destination_port=destination;
        const size_t udp_offset=14+(ipv6?40:20);
        const auto encoded=UetWireCodec::encode(noop_control(),network);
        CHECK(encoded[udp_offset+2]==destination/256 && encoded[udp_offset+3]==destination%256);
        const auto decoded=UetWireCodec::decode(encoded.data(),encoded.size(),crc,253,{},destination);
        CHECK(decoded.network.udp_destination_port==destination);
        CHECK(UetWireCodec::encode(decoded.packet,decoded.network)==encoded);
        check_throws<std::invalid_argument>([&] {
            UetWireCodec::decode(encoded.data(),encoded.size(),crc,253,{},static_cast<uint16_t>(destination+1));
        });
        // A trim keeps UDP's original destination and length. The destination
        // check still uses the fabric setting, while the length check is waived.
        auto trimmed=encoded; TrimmingOptions options;
        CHECK(UetWireCodec::trim_packet(trimmed,options));
        CHECK(UetWireCodec::decode(trimmed.data(),trimmed.size(),crc,253,options,destination).packet.trimmed);
        check_throws<std::invalid_argument>([&] {
            UetWireCodec::decode(trimmed.data(),trimmed.size(),crc,253,options,static_cast<uint16_t>(destination+1));
        });
        PDStoNET_pkt response{}; response.PDS_type=RUOD_ack_header;
        auto& ack=response.PDS_header.RUOD_ack_header;
        ack.type=ACK_CC; ack.next_hdr=UET_HDR_NONE; ack.cack_psn=1000; ack.spdcid=512; ack.dpdcid=7;
        auto acknowledgment=UetWireCodec::encode(response,network);
        CHECK(UetWireCodec::stamp_service_time(acknowledgment,256,128,crc,253,destination));
        CHECK(UetWireCodec::decode(acknowledgment.data(),acknowledgment.size(),crc,253,{},destination)
            .packet.congestion_ack.service_time==1);
    }
    WireOptions defaults; defaults.udp=true;
    const auto encoded=UetWireCodec::encode(noop_control(),defaults);
    // Independent default-port bytes from Table 3-35, not the production constant.
    CHECK(encoded[36]==0x12 && encoded[37]==0xb9);
}

void host_port_and_departure_stamp(bool ipv6,uint16_t destination,bool congestion) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    LinkConfig link; link.rate_bps=1000000000;
    fabric.add_link(1,2,link); fabric.add_link(2,1,link);
    WireOptions network; network.udp=true; network.ipv6=ipv6; network.udp_destination_port=destination;
    PdsHost target(2,loop,trace,target_port,PdsHost::WireFormat::Uet11,network);
    if (congestion) target.enable_nscc({});
    UET::SES::Endpoint target_endpoint(2,target,loop,trace); target_endpoint.memory().add_job(1);
    size_t replies=0;
    source.set_receiver([&](Frame frame) {
        if (frame.bytes.size()==1000) return; // Unrelated traffic occupies the reverse link first.
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),true,253,{},destination);
        CHECK(decoded.network.udp_destination_port==destination && decoded.packet.PDS_type==RUOD_ack_header);
        if (congestion) CHECK(decoded.packet.congestion_ack.service_time>1);
        ++replies;
    });
    WireOptions outgoing=network;
    if (ipv6) {
        outgoing.source.ip[0]=outgoing.destination.ip[0]=0xfd;
        outgoing.source.ip[15]=1; outgoing.destination.ip[15]=2;
    } else { outgoing.source.ip[3]=1; outgoing.destination.ip[3]=2; }
    Frame request; request.source=1; request.destination=2;
    outgoing.udp_destination_port=static_cast<uint16_t>(destination+1);
    request.bytes=UetWireCodec::encode(semantic_noop(),outgoing);
    CHECK(source.try_send(request)==SendResult::Accepted); loop.run();
    CHECK(replies==0 && target.manager().getPDSStatus().open_cnt==0);
    Frame background; background.source=2; background.destination=1; background.bytes.resize(1000);
    CHECK(target_port.try_send(background)==SendResult::Accepted);
    outgoing.udp_destination_port=destination; request.bytes=UetWireCodec::encode(semantic_noop(),outgoing);
    CHECK(source.try_send(request)==SendResult::Accepted); loop.run();
    CHECK(replies==1 && target.manager().getPDSStatus().open_cnt==1);
    CHECK(std::count_if(trace.events().begin(),trace.events().end(),[](const auto& event) {
        return event.node==2 && event.event=="malformed_frame";
    })==1);
    target_endpoint.close(); target.close(); CHECK(loop.pending()==0);
}
int main() {
    try {
        configurable_wire_port();
        for (const bool ipv6:{false,true}) for (const uint16_t destination:{0,49150,65535})
            for (const bool congestion:{false,true}) host_port_and_departure_stamp(ipv6,destination,congestion);
        std::cout<<"PASS UE default UDP port 4793, configurable 16-bit ports, mismatch drops, trimming and MAC stamping\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
