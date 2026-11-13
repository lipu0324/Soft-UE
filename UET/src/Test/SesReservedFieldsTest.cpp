#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>
using namespace UET::NetworkLayer;

// Fault injection changes only SES bytes in encoder-produced frames. Repair
// the CRC over its specified coverage (§3.5.26); IP/UDP lengths stay unchanged.
// A frame with a nonzero reserved bit still needs a valid integrity trailer.
void repair_crc(std::vector<uint8_t>& frame,const WireOptions& network) {
    if (!network.crc) return;
    const size_t start=14+(network.ipv6?8:12),end=frame.size()-4;
    const auto checksum=UetWireCodec::crc32c(frame.data()+start,end-start);
    for (size_t octet=0;octet<4;++octet) frame[end+octet]=checksum>>(24-8*octet);
}
PDStoNET_pkt request_packet(bool start_of_message,bool atomic) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
    auto& request=packet.PDS_header.RUOD_req_header;
    request.type=RUD_REQ; request.next_hdr=UET_HDR_REQUEST_STD; request.psn=1000;
    request.spdcid=1; request.dpdcid=512;
    packet.SESpkt.bth_type=Standard_Header;
    auto& semantic=packet.SESpkt.bth_header.Standard_Header;
    semantic.opcode=atomic?3:1; semantic.som=start_of_message; semantic.eom=1;
    semantic.rel=semantic.dc=1; semantic.msg_id=9; semantic.job_id=0x123456;
    semantic.PIDonFEP=0x789; semantic.resource_index=0xabc; semantic.request_length=3;
    if (!start_of_message) {
        semantic.diff.som_false.payload_length=3; semantic.diff.som_false.message_offset=4096;
        semantic.request_length=4099;
    }
    packet.SESpkt.payload={7,8,9}; return packet;
}
void request_reserved_fields(const WireOptions& network,bool start_of_message,bool atomic) {
    const auto original=request_packet(start_of_message,atomic);
    const auto canonical=UetWireCodec::encode(original,network);
    const size_t semantic_start=14+(network.ipv6?40:20)+(network.udp?8:4)+12;
    auto changed=canonical;
    changed[semantic_start]|=0xc0; // Reserved opcode prefix, not opcode bits.
    changed[semantic_start+8]|=0xf0; changed[semantic_start+10]|=0xf0;
    if (!start_of_message) {
        changed[semantic_start+32]=changed[semantic_start+33]=0xff;
        changed[semantic_start+34]|=0xc0; // 18 reserved bits above the 14-bit payload length.
    }
    if (atomic) changed[semantic_start+47]=0xff;
    if (network.crc)
        check_throws<std::invalid_argument>([&] { UetWireCodec::decode(changed.data(),changed.size(),true,253); });
    repair_crc(changed,network);
    const auto decoded=UetWireCodec::decode(changed.data(),changed.size(),network.crc,253).packet;
    const auto& semantic=decoded.SESpkt.bth_header.Standard_Header;
    CHECK(semantic.opcode==(atomic?3:1) && semantic.PIDonFEP==0x789 && semantic.resource_index==0xabc);
    CHECK(semantic.job_id==0x123456 && decoded.SESpkt.payload==original.SESpkt.payload);
    CHECK(UetWireCodec::encode(decoded,network)==canonical); // Reserved bits never leak into a new transmission.
    changed[semantic_start+1]|=0x40; repair_crc(changed,network);
    check_throws<std::invalid_argument>([&] { UetWireCodec::decode(changed.data(),changed.size(),network.crc,253); });
}
void response_reserved_fields(const WireOptions& network) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_ack_header;
    auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
    acknowledgment.type=ACK; acknowledgment.next_hdr=UET_HDR_RESPONSE_DATA;
    acknowledgment.cack_psn=1000; acknowledgment.spdcid=512; acknowledgment.dpdcid=1;
    packet.SESpkt.bth_type=Semantic_Response_with_Data_Header;
    auto& semantic=packet.SESpkt.bth_header.Semantic_Response_with_Data_Header;
    semantic.return_code=1; semantic.job_id=0x123456; semantic.response_message_id=9;
    semantic.read_request_msg_id=10; semantic.payload_length=3; semantic.modified_length=3;
    packet.SESpkt.payload={7,8,9};
    const auto canonical=UetWireCodec::encode(packet,network);
    const size_t semantic_start=14+(network.ipv6?40:20)+(network.udp?8:4)+12;
    auto changed=canonical;
    changed[semantic_start+4]=0xff; changed[semantic_start+10]|=0xc0;
    repair_crc(changed,network);
    const auto decoded=UetWireCodec::decode(changed.data(),changed.size(),network.crc,253).packet;
    CHECK(decoded.SESpkt.bth_header.Semantic_Response_with_Data_Header.job_id==0x123456);
    CHECK(decoded.SESpkt.bth_header.Semantic_Response_with_Data_Header.payload_length==3);
    CHECK(UetWireCodec::encode(decoded,network)==canonical);
    changed[semantic_start+1]|=0x40; repair_crc(changed,network);
    check_throws<std::invalid_argument>([&] { UetWireCodec::decode(changed.data(),changed.size(),network.crc,253); });
}
int main() {
    for (const bool ipv6:{false,true}) for (const bool udp:{false,true}) for (const bool crc:{false,true}) {
        WireOptions network; network.ipv6=ipv6; network.udp=udp; network.native_ip_protocol=253; network.crc=crc;
        for (const bool start_of_message:{false,true}) for (const bool atomic:{false,true})
            request_reserved_fields(network,start_of_message,atomic);
        response_reserved_fields(network);
    }
    std::cout<<"PASS SES reserved fields ignored, transmit canonicalization, version rejection and CRC enforcement\n";
}
