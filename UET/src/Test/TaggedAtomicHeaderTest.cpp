#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>
using namespace UET::NetworkLayer;

int main() {
    try {
        size_t cases=0;
        for (bool medium:{false,true}) for (uint8_t opcode:{uint8_t{0x0d},uint8_t{0x0e}})
            for (bool start:{false,true}) for (bool end:{false,true}) {
                if (medium && (!start || !end)) continue;
                for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (bool crc:{false,true}) {
                    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
                    packet.PDS_header.RUOD_req_header.type=RUD_REQ;
                    packet.PDS_header.RUOD_req_header.next_hdr=medium?UET_HDR_REQUEST_MEDIUM:UET_HDR_REQUEST_STD;
                    packet.SESpkt.bth_type=medium?Small_Message_RMA_Header:Standard_Header;
                    const auto fill=[&](auto& header) {
                        header.opcode=opcode; header.som=start; header.eom=end; header.rel=1;
                        header.job_id=1; header.PIDonFEP=2; header.resource_index=3;
                        header.request_length=8; header.initiator=0x12345678; header.match_bits=0xfedcba9876543210ULL;
                    };
                    if (medium) fill(packet.SESpkt.bth_header.Small_Message_RMA_Header);
                    else {
                        auto& header=packet.SESpkt.bth_header.Standard_Header; fill(header);
                        header.msg_id=9;
                        if (!start) { header.diff.som_false.message_offset=4; header.diff.som_false.payload_length=8; }
                    }
                    packet.SESpkt.eth_type=Atomic_Operation_Extension_Header;
                    auto& atomic=packet.SESpkt.eth_header.Atomic_Operation_Extension_Header;
                    atomic.atomic_opcode=0x0d; atomic.atomic_datatype=9; atomic.semantic_contol=3;
                    packet.SESpkt.payload={1,2,3,4,5,6,7,8};
                    WireOptions options; options.ipv6=ipv6; options.udp=udp; options.crc=crc; options.native_ip_protocol=253;
                    const auto bytes=UetWireCodec::encode(packet,options);
                    const size_t extension=14+(ipv6?40:20)+(udp?8:4)+12+(medium?32:44);
                    // Figure3-22/Table3-20: the atomic extension follows the
                    // complete request header for both tagged opcodes. These
                    // four literal bytes are independent of the decoder.
                    CHECK(bytes.size()>=extension+4);
                    CHECK(std::vector<uint8_t>(bytes.begin()+extension,bytes.begin()+extension+4)==
                        std::vector<uint8_t>({0x0d,0x09,0x03,0x00}));
                    const auto decoded=UetWireCodec::decode(bytes.data(),bytes.size(),crc,253);
                    CHECK(decoded.packet.SESpkt.eth_type==Atomic_Operation_Extension_Header && decoded.packet.SESpkt.payload==packet.SESpkt.payload);
                    const auto& actual=decoded.packet.SESpkt.eth_header.Atomic_Operation_Extension_Header;
                    CHECK(actual.atomic_opcode==0x0d && actual.atomic_datatype==9 && actual.semantic_contol==3);
                    for (size_t length=0;length<bytes.size();++length)
                        check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),length,crc,253); });
                    atomic.rsvd=1;
                    check_throws<std::invalid_argument>([&] { UetWireCodec::encode(packet,options); });
                    ++cases;
                }
            }
        CHECK(cases==80);
        std::cout << "PASS80 tagged atomic STD/MEDIUM extension goldens, fragment flags, carriers and truncation\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
