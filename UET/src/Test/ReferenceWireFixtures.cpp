#include "../Network_Layer/UetWireCodec.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

using namespace UET::NetworkLayer;
int main(int argument_count,char** arguments) {
    if (argument_count!=2) return 2;
    const std::filesystem::path output=arguments[1];
    std::filesystem::create_directories(output);
    size_t fixture_count=0;
    for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (const uint16_t port:{4793,49150})
        for (int type:{2,3,4,5,6,7,10,11}) {
        if (!udp && port!=4793) continue;
        PDStoNET_pkt packet{};
        if (type==2 || type==3 || type==4 || type==6) {
            packet.SESpkt.bth_type=Standard_Header;
            auto& semantic=packet.SESpkt.bth_header.Standard_Header;
            semantic.opcode=type==6?7:1; semantic.msg_id=type==6?0:0x1234;
            semantic.job_id=1; semantic.PIDonFEP=1; semantic.resource_index=1;
            semantic.som=semantic.eom=semantic.rel=1; semantic.dc=type!=6;
            semantic.request_length=3; packet.SESpkt.payload={0xaa,0xbb,0xcc};
            if (type==4) {
                packet.PDS_type=RUDI_header;
                auto& header=packet.PDS_header.RUDI_header;
                header.type=RUDI_REQ; header.next_hdr=UET_HDR_REQUEST_STD;
                header.pkt_id=0x12345678; header.flags.retx=1;
            } else if (type==6) {
                packet.PDS_type=UUD_req_header;
                packet.PDS_header.UUD_req_header={UUD_REQ,UET_HDR_REQUEST_STD};
            } else {
                packet.PDS_type=RUOD_req_header;
                auto& header=packet.PDS_header.RUOD_req_header;
                header.type=static_cast<PDS_type>(type); header.next_hdr=UET_HDR_REQUEST_STD;
                header.psn=1000; header.clear_psn_off=-3;
                header.spdcid=17; header.dpdcid=29;
            }
        } else if (type==5) {
            packet.PDS_type=RUDI_header;
            auto& header=packet.PDS_header.RUDI_header;
            header.type=RUDI_RESP; header.next_hdr=UET_HDR_RESPONSE;
            header.pkt_id=0x12345678; header.flags.retx=header.flags.m=1;
            packet.SESpkt.bth_type=Semantic_Response_Header;
            auto& semantic=packet.SESpkt.bth_header.Semantic_Response_Header;
            semantic.opcode=semantic.return_code=1; semantic.message_id=0x1234;
            semantic.job_id=1; semantic.modified_length=3;
        } else if (type==7) {
            packet.PDS_type=RUOD_ack_header;
            auto& header=packet.PDS_header.RUOD_ack_header;
            header.type=ACK; header.next_hdr=UET_HDR_NONE;
            header.cack_psn=1000; header.ack_psn_off=-3; header.spdcid=17; header.dpdcid=29;
        } else if (type==10) {
            packet.PDS_type=nack_header;
            auto& header=packet.PDS_header.nack_header;
            header.type=NACK; header.next_hdr=UET_HDR_NONE;
            header.nack_psn=1000; header.nack_code=UET_ROD_OOO;
            header.payload=998; header.spdcid=17; header.dpdcid=29;
        } else {
            packet.PDS_type=RUOD_cp_header;
            auto& header=packet.PDS_header.RUOD_cp_header;
            header.type=CP; header.ctl_type=Clear_cmd;
            header.psn=1000; header.payload=998; header.spdcid=17; header.dpdcid=29;
        }
        WireOptions network; network.ipv6=ipv6; network.udp=udp; network.native_ip_protocol=253; network.entropy=0xbeef;
        network.udp_destination_port=port;
        network.source.ip[0]=10; network.source.ip[3]=1;
        network.destination.ip[0]=10; network.destination.ip[3]=2;
        const auto frame=UetWireCodec::encode(packet,network);
        const auto name=std::to_string(type)+"-"+std::to_string(ipv6)+"-"+std::to_string(udp)+
            (port==4793?"":"-"+std::to_string(port))+".bin";
        std::ofstream file(output/name,std::ios::binary);
        file.write(reinterpret_cast<const char*>(frame.data()),frame.size());
        if (!file) return 1;
        ++fixture_count;
    }
    std::cout<<"Generated "<<fixture_count<<" independent-reference fixtures\n";
}
