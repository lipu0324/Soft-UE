#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>
using namespace UET::NetworkLayer;

PDStoNET_pkt request_packet() {
    PDStoNET_pkt p{}; p.PDS_type=RUOD_req_header;
    auto& r=p.PDS_header.RUOD_req_header;
    r.type=ROD_REQ; r.next_hdr=UET_HDR_REQUEST_STD; r.flags.syn=1; r.flags.ar=1;
    r.clear_psn_off=0xffff; r.psn=0x01020304; r.spdcid=0x11; r.psn_off=7;
    p.SESpkt.bth_type=Standard_Header; auto& h=p.SESpkt.bth_header.Standard_Header;
    h.opcode=5; h.dc=1; h.rel=1; h.som=1; h.eom=1; h.msg_id=0x1234;
    h.ri_generation=1; h.job_id=7; h.PIDonFEP=9; h.resource_index=10;
    h.buffer_offset=32; h.initiator=11; h.match_bits=0x1122334455667788ULL;
    h.request_length=3; p.SESpkt.payload={0xaa,0xbb,0xcc}; return p;
}
int main() {
    try {
        const std::string check="123456789";
        CHECK(UetWireCodec::crc32c(reinterpret_cast<const uint8_t*>(check.data()),check.size())==0xe3069283u);
        auto packet=request_packet();
        // Independently specified byte vector for UE 1.1 §§3.4.3.1, 3.5.10.
        const std::vector<uint8_t> expected={
            0x19,0x8c,0xff,0xff,1,2,3,4,0,0x11,0,7,
            5,0x2b,0x12,0x34,1,0,0,7,0,9,0,10,
            0,0,0,0,0,0,0,32,0,0,0,11,
            0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
            0,0,0,0,0,0,0,0,0,0,0,3,0xaa,0xbb,0xcc};
        for (bool ipv6 : {false,true}) for (bool udp : {false,true}) for (bool crc : {false,true}) {
            WireOptions o; o.ipv6=ipv6; o.udp=udp; o.crc=crc; o.entropy=0xbeef; o.ecn=2;
            o.source.ip[0]=10; o.source.ip[3]=1; o.destination.ip[0]=10; o.destination.ip[3]=2;
            auto bytes=UetWireCodec::encode(packet,o);
            const size_t start=14+(ipv6?40:20)+(udp?8:4);
            CHECK(std::vector<uint8_t>(bytes.begin()+start,bytes.begin()+start+expected.size())==expected);
            const auto decoded=UetWireCodec::decode(bytes.data(),bytes.size(),crc);
            CHECK(decoded.packet.PDS_header.RUOD_req_header.psn==0x01020304);
            CHECK(decoded.packet.SESpkt.payload==packet.SESpkt.payload);
            CHECK(decoded.network.ipv6==ipv6); CHECK(decoded.network.udp==udp);
            CHECK(decoded.network.entropy==0xbeef);
            UetWireCodec::mark_ecn(bytes);
            CHECK(UetWireCodec::decode(bytes.data(),bytes.size(),crc).network.ecn==3);
            if (!ipv6) {
                auto reserved=bytes; reserved[20]|=0x80; reserved[24]=reserved[25]=0;
                uint32_t sum=0;
                for (size_t i=14;i<34;i+=2) sum+=(uint16_t{reserved[i]}<<8)|reserved[i+1];
                while (sum>>16) sum=(sum&0xffff)+(sum>>16);
                const auto checksum=static_cast<uint16_t>(~sum);
                reserved[24]=checksum>>8; reserved[25]=checksum&255;
                check_throws<std::invalid_argument>([&] { UetWireCodec::decode(reserved.data(),reserved.size(),crc); });
            }
            if (crc) {
                bytes[start+expected.size()-1]^=1;
                check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),bytes.size(),true); });
            }
            for (size_t length=0; length<start+expected.size()+(crc?4:0); ++length)
                check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),length,crc); });
        }
        auto cp=packet; cp.PDS_type=RUOD_cp_header; cp.PDS_header={}; cp.SESpkt={};
        auto& control=cp.PDS_header.RUOD_cp_header; control.type=CP; control.ctl_type=9; control.psn=7;
        const auto control_bytes=UetWireCodec::encode(cp,{});
        CHECK(UetWireCodec::decode(control_bytes.data(),control_bytes.size()).packet.PDS_header.RUOD_cp_header.ctl_type==9);
        auto unsupported=packet; unsupported.SESpkt.bth_header.Standard_Header.version=1;
        check_throws<std::invalid_argument>([&] { UetWireCodec::encode(unsupported,{}); });
        std::cout << "PASS: golden PDS/SES bytes, eight IP/UDP/CRC combinations, corruption, ECN and truncation\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
