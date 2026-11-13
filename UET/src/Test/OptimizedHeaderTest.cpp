#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>
using namespace UET::NetworkLayer;

static PDStoNET_pkt request(bool medium,uint8_t opcode) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
    auto& transport=packet.PDS_header.RUOD_req_header;
    transport.type=RUD_REQ; transport.next_hdr=medium?UET_HDR_REQUEST_MEDIUM:UET_HDR_REQUEST_SMALL;
    transport.psn=0x89abcdef; transport.clear_psn_off=-1; transport.spdcid=17; transport.dpdcid=29;
    packet.SESpkt.bth_type=medium?Small_Message_RMA_Header:Optimized_Header;
    const auto fill=[&](auto& header) {
        header.opcode=opcode; header.som=header.eom=header.rel=header.dc=1;
        header.request_length=8; header.ri_generation=0x44; header.job_id=0x012345;
        header.PIDonFEP=0x123; header.resource_index=0x456; header.buffer_offset=0x0123456789abcdefULL;
    };
    if (medium) {
        auto& header=packet.SESpkt.bth_header.Small_Message_RMA_Header; fill(header);
        header.hd=opcode==5 || opcode==16; header.initiator=0x12345678; header.match_bits=0xfedcba9876543210ULL;
    } else fill(packet.SESpkt.bth_header.Optimized_Header);
    if (opcode!=2) packet.SESpkt.payload={1,2,3,4,5,6,7,8};
    if (opcode==16 || opcode==17) {
        packet.SESpkt.eth_type=opcode==17?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header;
        auto& group=opcode==17?packet.SESpkt.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
            packet.SESpkt.eth_header.Synchronized_Operation_Extension_Header;
        group.sync_group=0x1234; group.sync_count=opcode==17 || medium?2:0;
    }
    if (opcode==3 || opcode==4 || opcode==17) {
        if (opcode!=17) packet.SESpkt.eth_type=Atomic_Operation_Extension_Header;
        auto& atomic=opcode==17?packet.SESpkt.eth_header.Synchronized_Atomic_Extension_Headers.atomic:
            packet.SESpkt.eth_header.Atomic_Operation_Extension_Header;
        atomic.atomic_opcode=12; atomic.atomic_datatype=7;
    }
    return packet;
}
static std::vector<uint8_t> request_golden(bool medium,uint8_t opcode) {
    std::vector<uint8_t> bytes={opcode,static_cast<uint8_t>(medium && (opcode==5 || opcode==16)?0x2f:0x2b),0,8,
        0x44,0x01,0x23,0x45,0x01,0x23,0x04,0x56,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    if (medium) bytes.insert(bytes.end(),{0x12,0x34,0x56,0x78,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10});
    if (opcode==16 || opcode==17) bytes.insert(bytes.end(),{0x12,0x34,0,static_cast<uint8_t>(opcode==17 || medium?2:0)});
    if (opcode==3 || opcode==4 || opcode==17) bytes.insert(bytes.end(),{12,7,0,0});
    return bytes;
}
static void verify(PDStoNET_pkt packet,const std::vector<uint8_t>& semantic,bool ipv6,bool udp,bool crc) {
    WireOptions options; options.ipv6=ipv6; options.udp=udp; options.crc=crc; options.native_ip_protocol=253;
    auto bytes=UetWireCodec::encode(packet,options);
    const size_t start=14+(ipv6?40:20)+(udp?8:4)+12;
    CHECK(bytes.size()>=start+semantic.size() && std::equal(semantic.begin(),semantic.end(),bytes.begin()+start));
    const auto decoded=UetWireCodec::decode(bytes.data(),bytes.size(),crc,253);
    CHECK(decoded.packet.SESpkt.bth_type==packet.SESpkt.bth_type && decoded.packet.SESpkt.payload==packet.SESpkt.payload);
    if (packet.SESpkt.bth_type==Optimized_Header) {
        const auto& header=decoded.packet.SESpkt.bth_header.Optimized_Header;
        CHECK(header.request_length==8 && header.job_id==0x012345 && header.buffer_offset==0x0123456789abcdefULL && !header.hd);
    } else if (packet.SESpkt.bth_type==Small_Message_RMA_Header) {
        const auto& header=decoded.packet.SESpkt.bth_header.Small_Message_RMA_Header;
        CHECK(header.request_length==8 && header.initiator==0x12345678 && header.match_bits==0xfedcba9876543210ULL);
    } else CHECK(decoded.packet.SESpkt.bth_header.Optimized_Response_with_Data_Header.original_request_psn==0x89abcdef);
    for (size_t length=0;length<bytes.size();++length)
        check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),length,crc,253); });
    if (!crc) {
        bytes[start+2]|=0xc0;
        if (packet.SESpkt.bth_type==Optimized_Response_with_Data_Header) bytes[start+4]=0xff;
        else { bytes[start]|=0xc0; bytes[start+8]|=0xf0; bytes[start+10]|=0xf0;
            if (packet.SESpkt.bth_type==Optimized_Header) bytes[start+1]|=4; }
        const auto reserved=UetWireCodec::decode(bytes.data(),bytes.size(),false,253);
        CHECK(reserved.packet.SESpkt.payload==packet.SESpkt.payload);
        bytes[start+1]|=0xc0;
        check_throws<std::invalid_argument>([&] { UetWireCodec::decode(bytes.data(),bytes.size(),false,253); });
    }
}
int main() {
    try {
        size_t cases=0;
        for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (bool crc:{false,true}) {
            for (bool medium:{false,true}) for (uint8_t opcode:{1,2,3,4,16,17}) {
                verify(request(medium,opcode),request_golden(medium,opcode),ipv6,udp,crc); ++cases;
            }
            verify(request(true,5),request_golden(true,5),ipv6,udp,crc); ++cases;
            for (bool data:{false,true}) {
                PDStoNET_pkt packet{}; packet.PDS_type=RUOD_ack_header;
                auto& transport=packet.PDS_header.RUOD_ack_header;
                transport.type=ACK; transport.next_hdr=UET_HDR_RESPONSE_DATA_SMALL;
                packet.SESpkt.bth_type=Optimized_Response_with_Data_Header;
                auto& header=packet.SESpkt.bth_header.Optimized_Response_with_Data_Header;
                header.opcode=data?2:1; header.return_code=data?1:0x1c; header.payload_length=data?8:0;
                header.job_id=0x012345; header.original_request_psn=0x89abcdef;
                if (data) packet.SESpkt.payload={1,2,3,4,5,6,7,8};
                verify(packet,{static_cast<uint8_t>(data?2:1),static_cast<uint8_t>(data?1:0x1c),0,static_cast<uint8_t>(data?8:0),
                    0,0x01,0x23,0x45,0x89,0xab,0xcd,0xef},ipv6,udp,crc); ++cases;
            }
        }
        auto invalid=request(false,1); invalid.SESpkt.bth_header.Optimized_Header.request_length=0x4000;
        check_throws<std::invalid_argument>([&] { UetWireCodec::encode(invalid,{}); });
        invalid=request(false,1); invalid.SESpkt.bth_header.Optimized_Header.hd=1;
        check_throws<std::invalid_argument>([&] { UetWireCodec::encode(invalid,{}); });
        for (uint16_t length:{uint16_t{0},uint16_t{8192},uint16_t{0x3fff}}) {
            auto boundary=request(false,2); boundary.SESpkt.bth_header.Optimized_Header.request_length=length;
            const auto bytes=UetWireCodec::encode(boundary,{});
            const auto decoded=UetWireCodec::decode(bytes.data(),bytes.size());
            CHECK(decoded.packet.SESpkt.bth_header.Optimized_Header.request_length==length);
            // The codec preserves the14-bit field; semantic MTU admission is
            // separate and not enabled by this wire-format regression.
        }
        CHECK(cases==120); std::cout<<"PASS120 optimized20/32/12-byte header goldens, extensions, carriers, versions, reserved bits and truncation\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
