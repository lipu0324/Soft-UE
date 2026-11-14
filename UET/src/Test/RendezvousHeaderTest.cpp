#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>
using namespace UET::NetworkLayer;

int main() {
    try {
        // UE1.1 Figure3-21, independently transcribed from the rendered PDF:
        // 32-bit eager, 8/12/12-bit read addressing, 64-bit offset and key.
        const std::vector<uint8_t> expected={
            0,0,0,3,0xab,0x12,0x34,0x56,
            1,2,3,4,5,6,7,8,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        for (uint8_t opcode:{6,10}) for (bool first:{false,true}) for (bool ipv6:{false,true})
            for (bool udp:{false,true}) for (bool crc:{false,true}) {
                PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
                packet.PDS_header.RUOD_req_header.type=RUD_REQ;
                packet.PDS_header.RUOD_req_header.next_hdr=UET_HDR_REQUEST_STD;
                packet.SESpkt.bth_type=Standard_Header; packet.SESpkt.eth_type=Rendezvous_Extension_Header;
                auto& header=packet.SESpkt.bth_header.Standard_Header;
                header.opcode=opcode; header.som=first; header.eom=1; header.rel=1; header.dc=1;
                header.msg_id=1; header.job_id=1; header.PIDonFEP=1; header.resource_index=1;
                header.request_length=73;
                if (!first) { header.diff.som_false.payload_length=3; header.diff.som_false.message_offset=0; }
                auto& rendezvous=packet.SESpkt.eth_header.Rendezvous_Extension_Header;
                rendezvous.eager_length=3; rendezvous.read_ri_generation=0xab;
                rendezvous.read_PIDonFEP=0x123; rendezvous.read_resource_index=0x456;
                rendezvous.read_offset=0x0102030405060708ULL; rendezvous.read_mem_key=0x8899aabbccddeeffULL;
                packet.SESpkt.payload={0x6a,0x6b,0x6c};
                WireOptions options; options.ipv6=ipv6; options.udp=udp; options.crc=crc; options.native_ip_protocol=253;
                const auto bytes=UetWireCodec::encode(packet,options);
                const size_t start=14+(ipv6?40:20)+(udp?8:4)+12+44;
                CHECK(bytes.size()>=start+expected.size());
                CHECK(std::vector<uint8_t>(bytes.begin()+start,bytes.begin()+start+24)==expected);
                const auto decoded=UetWireCodec::decode(bytes.data(),bytes.size(),crc,253);
                const auto& actual=decoded.packet.SESpkt.eth_header.Rendezvous_Extension_Header;
                CHECK(decoded.packet.SESpkt.eth_type==Rendezvous_Extension_Header &&
                    decoded.packet.SESpkt.bth_header.Standard_Header.opcode==opcode &&
                    actual.eager_length==3 && actual.read_ri_generation==0xab && actual.read_PIDonFEP==0x123 &&
                    actual.read_resource_index==0x456 && actual.read_offset==0x0102030405060708ULL &&
                    actual.read_mem_key==0x8899aabbccddeeffULL && decoded.packet.SESpkt.payload==packet.SESpkt.payload);
                CHECK(decoded.nominal_packet_size==12+44+24+3+(udp?8:4)+(crc?4:0)+40);
                for (size_t length=0;length<bytes.size();++length)
                    check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),length,crc,253); });
                packet.SESpkt.eth_type=Atomic_Operation_Extension_Header;
                check_throws<std::invalid_argument>([&] { UetWireCodec::encode(packet,options); });
            }
        std::cout<<"PASS rendezvous extension golden bytes on every SEND/TSEND fragment, both IP/carrier/CRC modes and truncated/wrong headers\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
