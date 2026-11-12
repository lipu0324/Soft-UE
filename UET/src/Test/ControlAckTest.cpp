#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>
using namespace UET::NetworkLayer;

int main() {
    try {
        PDStoNET_pkt acknowledgement{}; acknowledgement.PDS_type=RUOD_ack_header;
        auto& header=acknowledgement.PDS_header.RUOD_ack_header;
        header.type=ACK; header.next_hdr=UET_HDR_CP_ACK; header.cack_psn=42;
        header.spdcid=512; header.dpdcid=7;
        acknowledgement.control_ack.cp_ack_type=Close_cmd;
        WireOptions options; options.crc=false;
        auto bytes=UetWireCodec::encode(acknowledgement,options);
        // Independent §3.5.16.4.1 field locations: ACK starts at byte 38;
        // next-header=9, followed by an eight-byte Close Command ACK payload.
        CHECK(bytes.size()==58 && bytes[38]==0x3c && bytes[39]==0x80);
        CHECK(std::vector<uint8_t>(bytes.begin()+50,bytes.end())==std::vector<uint8_t>({4,2,0,0,0,0,0,0}));
        const auto decoded=UetWireCodec::decode(bytes.data(),bytes.size(),false).packet;
        CHECK(decoded.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_CP_ACK);
        CHECK(decoded.control_ack.cp_ack_type==Close_cmd && decoded.control_ack.cp_ack_length==2);
        bytes[51]=7;
        check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),bytes.size(),false); });
        acknowledgement.control_ack.start_psn_method=1;
        acknowledgement.control_ack.expected_psn=0xfedcba98;
        options.crc=true; bytes=UetWireCodec::encode(acknowledgement,options);
        CHECK(UetWireCodec::decode(bytes.data(),bytes.size()).packet.control_ack.expected_psn==0xfedcba98);
        std::cout<<"PASS: UE 1.1 Close Command CP ACK layout, CRC and malformed-length rejection\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
