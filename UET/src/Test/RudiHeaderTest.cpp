#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>
using namespace UET::NetworkLayer;

PDStoNET_pkt packet(unsigned form,uint32_t identifier,bool retransmitted,bool marked) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUDI_header;
    auto& transport=packet.PDS_header.RUDI_header;
    transport.type=form<2?RUDI_REQ:RUDI_RESP; transport.flags.retx=retransmitted; transport.flags.m=marked;
    transport.pkt_id=identifier;
    if (form<2) {
        transport.next_hdr=UET_HDR_REQUEST_STD; packet.SESpkt.bth_type=Standard_Header;
        auto& header=packet.SESpkt.bth_header.Standard_Header;
        header.opcode=form?2:1; header.som=header.eom=header.rel=header.dc=1;
        header.job_id=header.PIDonFEP=header.resource_index=1; header.msg_id=9; header.request_length=3;
        if (!form) packet.SESpkt.payload={0x11,0x22,0x33};
    } else if (form==2) {
        transport.next_hdr=UET_HDR_RESPONSE; packet.SESpkt.bth_type=Semantic_Response_Header;
        auto& header=packet.SESpkt.bth_header.Semantic_Response_Header;
        header.opcode=header.return_code=1; header.job_id=1; header.message_id=9; header.modified_length=3;
    } else {
        transport.next_hdr=UET_HDR_RESPONSE_DATA; packet.SESpkt.bth_type=Semantic_Response_with_Data_Header;
        auto& header=packet.SESpkt.bth_header.Semantic_Response_with_Data_Header;
        header.opcode=2; header.return_code=1; header.job_id=1; header.read_request_msg_id=9;
        header.response_message_id=17; header.payload_length=header.modified_length=3;
        packet.SESpkt.payload={0x11,0x22,0x33};
    }
    return packet;
}
int main() {
    try {
        size_t cases=0;
        for (unsigned form=0;form<4;++form) for (bool marked:{false,true}) {
            if (form<2 && marked) continue;
            for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (bool crc:{false,true})
                for (bool retransmitted:{false,true}) for (uint32_t identifier:{0u,0xabcd1234u,UINT32_MAX}) {
                auto original=packet(form,identifier,retransmitted,marked);
                WireOptions network; network.ipv6=ipv6; network.udp=udp; network.crc=crc; network.native_ip_protocol=253;
                auto bytes=UetWireCodec::encode(original,network);
                const size_t start=14+(ipv6?40:20)+(udp?8:4);
                // Independent Figure3-74 prologue, reserved word and BE ID.
                // STD next-header is3, RESPONSE4 and RESPONSE_DATA5.
                const std::vector<uint8_t> golden={
                    static_cast<uint8_t>(form<2?0x21:0x2a),
                    static_cast<uint8_t>((form<2 || form==3?0x80:0)|(marked?0x20:0)|(retransmitted?0x10:0)),
                    0,0,static_cast<uint8_t>(identifier>>24),static_cast<uint8_t>(identifier>>16),
                    static_cast<uint8_t>(identifier>>8),static_cast<uint8_t>(identifier)};
                CHECK(std::vector<uint8_t>(bytes.begin()+start,bytes.begin()+start+8)==golden);
                const auto decoded=UetWireCodec::decode(bytes.data(),bytes.size(),crc,253);
                const auto& header=decoded.packet.PDS_header.RUDI_header;
                CHECK(decoded.packet.PDS_type==RUDI_header && header.type==original.PDS_header.RUDI_header.type &&
                    header.pkt_id==identifier && header.flags.retx==retransmitted && header.flags.m==marked &&
                    header.next_hdr==original.PDS_header.RUDI_header.next_hdr);
                CHECK(decoded.packet.SESpkt.payload==original.SESpkt.payload);
                const size_t semantic_bytes=form<2?44:form==2?12:20;
                CHECK(decoded.nominal_packet_size==40+(udp?8:4)+8+semantic_bytes+original.SESpkt.payload.size()+(crc?4:0));
                for (size_t length=0;length<bytes.size();++length)
                    check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),length,crc,253); });
                if (!crc) {
                    bytes[start+1]|=form<2?0x6f:0x4f; bytes[start+2]=0xab; bytes[start+3]=0xcd;
                    const auto reserved=UetWireCodec::decode(bytes.data(),bytes.size(),false,253);
                    CHECK(reserved.packet.PDS_header.RUDI_header.pkt_id==identifier &&
                        reserved.packet.PDS_header.RUDI_header.flags.m==marked);
                }
                ++cases;
            }
        }
        auto invalid=packet(0,9,false,false); invalid.PDS_header.RUDI_header.flags.m=1;
        check_throws<std::invalid_argument>([&] { UetWireCodec::encode(invalid,{}); });
        invalid=packet(0,9,false,false); invalid.PDS_header.RUDI_header.flags.retx=2;
        check_throws<std::invalid_argument>([&] { UetWireCodec::encode(invalid,{}); });
        invalid=packet(0,9,false,false); invalid.PDS_header.RUDI_header.type=ACK;
        check_throws<std::invalid_argument>([&] { UetWireCodec::encode(invalid,{}); });
        CHECK(cases==288); std::cout<<"PASS288 RUDI header goldens, request/response/data boundaries, reserved bits and truncation\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
