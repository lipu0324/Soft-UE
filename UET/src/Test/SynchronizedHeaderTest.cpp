#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>
using namespace UET::NetworkLayer;

int main() {
    try {
        for (bool atomic:{false,true}) for (bool start:{false,true}) for (bool end:{false,true})
            for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (bool crc:{false,true}) {
                PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
                packet.PDS_header.RUOD_req_header.type=RUD_REQ;
                packet.PDS_header.RUOD_req_header.next_hdr=UET_HDR_REQUEST_STD;
                packet.SESpkt.bth_type=Standard_Header;
                packet.SESpkt.eth_type=atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header;
                auto& header=packet.SESpkt.bth_header.Standard_Header;
                header.opcode=atomic?0x11:0x10; header.som=start; header.eom=end; header.rel=1;
                header.msg_id=1; header.job_id=1; header.PIDonFEP=1; header.resource_index=1;
                header.request_length=8;
                if (!start) { header.diff.som_false.message_offset=4; header.diff.som_false.payload_length=3; }
                auto& synchronization=atomic?packet.SESpkt.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
                    packet.SESpkt.eth_header.Synchronized_Operation_Extension_Header;
                synchronization.sync_group=0xabcd; synchronization.sync_count=0x0123;
                if (atomic) {
                    auto& operation=packet.SESpkt.eth_header.Synchronized_Atomic_Extension_Headers.atomic;
                    operation.atomic_opcode=2; operation.atomic_datatype=7;
                }
                packet.SESpkt.payload={0x6a,0x6b,0x6c};
                WireOptions options; options.ipv6=ipv6; options.udp=udp; options.crc=crc; options.native_ip_protocol=253;
                const auto bytes=UetWireCodec::encode(packet,options);
                const size_t extension_start=14+(ipv6?40:20)+(udp?8:4)+12+44;
                // Literal byte order comes from Figure3-24 PDF index233;
                // SYNC_ATOMIC order is independently specified by Table3-20.
                const std::vector<uint8_t> expected=atomic?std::vector<uint8_t>{0xab,0xcd,1,0x23,2,7,0,0}:
                    std::vector<uint8_t>{0xab,0xcd,1,0x23};
                CHECK(bytes.size()>=extension_start+expected.size());
                CHECK(std::vector<uint8_t>(bytes.begin()+extension_start,bytes.begin()+extension_start+expected.size())==expected);
                const auto decoded=UetWireCodec::decode(bytes.data(),bytes.size(),crc,253);
                CHECK(decoded.packet.SESpkt.eth_type==packet.SESpkt.eth_type && decoded.packet.SESpkt.payload==packet.SESpkt.payload);
                const auto& actual=atomic?decoded.packet.SESpkt.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
                    decoded.packet.SESpkt.eth_header.Synchronized_Operation_Extension_Header;
                CHECK(actual.sync_group==0xabcd && actual.sync_count==0x0123);
                if (atomic) {
                    const auto& operation=decoded.packet.SESpkt.eth_header.Synchronized_Atomic_Extension_Headers.atomic;
                    CHECK(operation.atomic_opcode==2 && operation.atomic_datatype==7 && !operation.semantic_contol && !operation.rsvd);
                }
                CHECK(decoded.nominal_packet_size==12+44+expected.size()+3+(udp?8:4)+(crc?4:0)+40);
                for (size_t length=0;length<bytes.size();++length)
                    check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),length,crc,253); });
                packet.SESpkt.eth_type=Atomic_Operation_Extension_Header;
                check_throws<std::invalid_argument>([&] { UetWireCodec::encode(packet,options); });
            }
        std::cout<<"PASS synchronized WRITE/ATOMIC standard extensions, independent golden order, all fragments/carriers and truncation\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
