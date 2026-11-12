#include "UetWireCodec.hpp"
#include <algorithm>
#include <stdexcept>

namespace UET::NetworkLayer {
namespace {
using Bytes = std::vector<uint8_t>;
void put(Bytes& out, uint64_t value, size_t width) {
    for (size_t i=width; i>0; --i) out.push_back(static_cast<uint8_t>(value >> ((i-1)*8)));
}
uint64_t get(const uint8_t* p, size_t width) {
    uint64_t value = 0;
    for (size_t i=0; i<width; ++i) value = (value << 8) | p[i];
    return value;
}
class Reader {
public:
    Reader(const uint8_t* bytes, size_t size) : bytes_(bytes), size_(size) {}
    uint64_t take(size_t width) {
        if (width > size_ - offset_) throw std::invalid_argument("truncated UET header");
        const auto value = get(bytes_+offset_,width); offset_ += width; return value;
    }
    Bytes rest() const { return Bytes(bytes_+offset_,bytes_+size_); }
private:
    const uint8_t* bytes_;
    size_t size_, offset_ = 0;
};
uint16_t ip_checksum(const uint8_t* bytes) {
    uint32_t sum = 0;
    for (size_t i=0; i<20; i+=2) sum += static_cast<uint16_t>(get(bytes+i,2));
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}
uint8_t next_wire(PDS_next_hdr next) {
    switch (next) {
    case UET_HDR_NONE: return 0;
    case UET_HDR_REQUEST_SMALL: return 1;
    case UET_HDR_REQUEST_MEDIUM: return 2;
    case UET_HDR_REQUEST_STD: return 3;
    case UET_HDR_RESPONSE: return 4;
    case UET_HDR_RESPONSE_DATA: return 5;
    case UET_HDR_RESPONSE_DATA_SMALL: return 6;
    default: throw std::invalid_argument("invalid next header");
    }
}
PDS_next_hdr next_host(uint8_t next) {
    static constexpr PDS_next_hdr names[] = {UET_HDR_NONE,UET_HDR_REQUEST_SMALL,
        UET_HDR_REQUEST_MEDIUM,UET_HDR_REQUEST_STD,UET_HDR_RESPONSE,
        UET_HDR_RESPONSE_DATA,UET_HDR_RESPONSE_DATA_SMALL};
    if (next > 6) throw std::invalid_argument("unsupported next header");
    return names[next];
}
void put_semantic(Bytes& out, const PDStoNET_pkt& packet, PDS_next_hdr next) {
    if (next == UET_HDR_NONE) {
        if (!packet.SESpkt.payload.empty()) throw std::invalid_argument("payload without SES header");
        return;
    }
    if (next == UET_HDR_REQUEST_STD) {
        if (packet.SESpkt.bth_type != Standard_Header) throw std::invalid_argument("SES header type mismatch");
        const auto& h = packet.SESpkt.bth_header.Standard_Header;
        if (h.version != 0) throw std::invalid_argument("unsupported SES version");
        put(out,h.opcode,1);
        put(out,(h.dc<<5)|(h.ie<<4)|(h.rel<<3)|(h.hd<<2)|(h.eom<<1)|h.som,1);
        put(out,h.msg_id,2); put(out,(uint32_t{h.ri_generation}<<24)|h.job_id,4);
        put(out,h.PIDonFEP,2); put(out,h.resource_index,2);
        put(out,h.buffer_offset,8); put(out,h.initiator,4); put(out,h.match_bits,8);
        if (h.som) put(out,h.diff.som_true.header_data,8);
        else put(out,(uint64_t{h.diff.som_false.payload_length}<<32)|h.diff.som_false.message_offset,8);
        put(out,h.request_length,4);
    } else if (next == UET_HDR_RESPONSE) {
        if (packet.SESpkt.bth_type != Semantic_Response_Header) throw std::invalid_argument("SES header type mismatch");
        const auto& h = packet.SESpkt.bth_header.Semantic_Response_Header;
        if (h.version != 0) throw std::invalid_argument("unsupported SES version");
        put(out,(h.list<<6)|h.opcode,1); put(out,h.return_code,1); put(out,h.message_id,2);
        put(out,(uint32_t{h.ri_generation}<<24)|h.job_id,4); put(out,h.modified_length,4);
    } else if (next == UET_HDR_RESPONSE_DATA) {
        if (packet.SESpkt.bth_type != Semantic_Response_with_Data_Header) throw std::invalid_argument("SES header type mismatch");
        const auto& h = packet.SESpkt.bth_header.Semantic_Response_with_Data_Header;
        if (h.version != 0) throw std::invalid_argument("unsupported SES version");
        put(out,(h.list<<6)|h.opcode,1); put(out,h.return_code,1); put(out,h.response_message_id,2);
        put(out,h.job_id,4); put(out,h.read_request_msg_id,2); put(out,h.payload_length,2);
        put(out,h.modified_length,4); put(out,h.message_offset,4);
    } else throw std::invalid_argument("SES wire format not implemented");
    out.insert(out.end(),packet.SESpkt.payload.begin(),packet.SESpkt.payload.end());
}
void get_semantic(Reader& r, PDStoNET_pkt& packet, PDS_next_hdr next) {
    if (next == UET_HDR_NONE) {
        if (!r.rest().empty()) throw std::invalid_argument("unexpected UET payload");
        return;
    }
    if (next == UET_HDR_REQUEST_STD) {
        packet.SESpkt.bth_type = Standard_Header;
        auto& h = packet.SESpkt.bth_header.Standard_Header;
        const auto opcode=r.take(1), flags=r.take(1);
        if ((opcode&0xc0)||(flags&0xc0)) throw std::invalid_argument("reserved SES bits or unsupported version");
        h.opcode=opcode; h.dc=(flags>>5)&1; h.ie=(flags>>4)&1; h.rel=(flags>>3)&1;
        h.hd=(flags>>2)&1; h.eom=(flags>>1)&1; h.som=flags&1;
        h.msg_id=r.take(2); const auto job=r.take(4); h.ri_generation=job>>24; h.job_id=job&0xffffff;
        const auto pid=r.take(2), ri=r.take(2);
        if ((pid&0xf000)||(ri&0xf000)) throw std::invalid_argument("reserved address bits");
        h.PIDonFEP=pid; h.resource_index=ri; h.buffer_offset=r.take(8);
        h.initiator=r.take(4); h.match_bits=r.take(8); const auto data=r.take(8);
        if (h.som) h.diff.som_true.header_data=data;
        else {
            if (data>>46) throw std::invalid_argument("reserved SES payload bits");
            h.diff.som_false.payload_length=(data>>32)&0x3fff;
            h.diff.som_false.message_offset=data&0xffffffff;
        }
        h.request_length=r.take(4);
    } else if (next == UET_HDR_RESPONSE) {
        packet.SESpkt.bth_type=Semantic_Response_Header;
        auto& h=packet.SESpkt.bth_header.Semantic_Response_Header;
        const auto op=r.take(1), code=r.take(1);
        if (code&0xc0) throw std::invalid_argument("unsupported SES response version");
        h.list=op>>6; h.opcode=op&0x3f; h.return_code=code; h.message_id=r.take(2);
        const auto job=r.take(4); h.ri_generation=job>>24; h.job_id=job&0xffffff;
        h.modified_length=r.take(4);
    } else if (next == UET_HDR_RESPONSE_DATA) {
        packet.SESpkt.bth_type=Semantic_Response_with_Data_Header;
        auto& h=packet.SESpkt.bth_header.Semantic_Response_with_Data_Header;
        const auto op=r.take(1), code=r.take(1);
        if (code&0xc0) throw std::invalid_argument("unsupported SES response version");
        h.list=op>>6; h.opcode=op&0x3f; h.return_code=code; h.response_message_id=r.take(2);
        const auto job=r.take(4); if (job>>24) throw std::invalid_argument("reserved response bits");
        h.job_id=job; h.read_request_msg_id=r.take(2); const auto length=r.take(2);
        if (length>>14) throw std::invalid_argument("reserved response payload bits");
        h.payload_length=length; h.modified_length=r.take(4); h.message_offset=r.take(4);
    } else throw std::invalid_argument("SES wire format not implemented");
    packet.SESpkt.payload=r.rest();
}
Bytes encode_pds(const PDStoNET_pkt& packet) {
    Bytes out; PDS_next_hdr next=UET_HDR_NONE;
    if (packet.PDS_type == RUOD_req_header) {
        const auto& h=packet.PDS_header.RUOD_req_header;
        if (h.type!=RUD_REQ && h.type!=ROD_REQ) throw std::invalid_argument("unsupported request type");
        next=h.next_hdr;
        put(out,(uint16_t{h.type}<<11)|(next_wire(next)<<7)|(h.flags.retx<<4)|(h.flags.ar<<3)|(h.flags.syn<<2),2);
        put(out,h.clear_psn_off,2); put(out,h.psn,4); put(out,h.spdcid,2);
        put(out,h.flags.syn ? (h.pdc_info<<12)|h.psn_off : h.dpdcid,2);
    } else if (packet.PDS_type == RUOD_ack_header) {
        const auto& h=packet.PDS_header.RUOD_ack_header;
        if (h.type!=ACK) throw std::invalid_argument("ACK extension not implemented");
        next=h.next_hdr;
        put(out,(7<<11)|(next_wire(next)<<7)|(h.flags.m<<5)|(h.flags.retx<<4)|(h.flags.p<<3)|(h.flags.req<<1),2);
        put(out,static_cast<uint16_t>(h.ack_psn_off),2); put(out,h.cack_psn,4); put(out,h.spdcid,2); put(out,h.dpdcid,2);
    } else if (packet.PDS_type == nack_header) {
        const auto& h=packet.PDS_header.nack_header;
        if (h.type!=NACK || h.next_hdr!=UET_HDR_NONE) throw std::invalid_argument("unsupported NACK format");
        put(out,(10<<11)|(h.flags.m<<5)|(h.flags.retx<<4)|(h.flags.nt<<3),2);
        put(out,h.nack_code,1); put(out,h.vendor_code,1); put(out,h.nack_psn,4);
        put(out,h.spdcid,2); put(out,h.dpdcid,2); put(out,h.payload,4);
    } else if (packet.PDS_type == RUOD_cp_header) {
        const auto& h=packet.PDS_header.RUOD_cp_header;
        if (h.type!=CP) throw std::invalid_argument("invalid CP type");
        put(out,(11<<11)|(h.ctl_type<<7)|(h.flags.isrod<<5)|(h.flags.retx<<4)|(h.flags.ar<<3)|(h.flags.syn<<2),2);
        put(out,h.probe_opaque,2); put(out,h.psn,4); put(out,h.spdcid,2);
        put(out,h.flags.syn ? (h.pdc_info<<12)|h.psn_off : h.dpdcid,2); put(out,h.payload,4);
    } else throw std::invalid_argument("PDS wire format not implemented");
    put_semantic(out,packet,next);
    return out;
}
PDStoNET_pkt decode_pds(const uint8_t* bytes, size_t size) {
    PDStoNET_pkt packet{}; Reader r(bytes,size);
    const auto prologue=r.take(2), type=prologue>>11, flags=prologue&0x7f;
    PDS_next_hdr next=type==11 ? UET_HDR_NONE : next_host((prologue>>7)&0xf);
    if (type==2 || type==3) {
        if (flags&0x63) throw std::invalid_argument("reserved PDS request flags");
        packet.PDS_type=RUOD_req_header; auto& h=packet.PDS_header.RUOD_req_header;
        h.type=static_cast<PDS_type>(type); h.next_hdr=next;
        h.flags.retx=(flags>>4)&1; h.flags.ar=(flags>>3)&1; h.flags.syn=(flags>>2)&1;
        h.clear_psn_off=r.take(2); h.psn=r.take(4); h.spdcid=r.take(2);
        const auto destination=r.take(2);
        if (h.flags.syn) { h.pdc_info=destination>>12; h.psn_off=destination&0xfff; }
        else h.dpdcid=destination;
    } else if (type==7) {
        if (flags&0x41) throw std::invalid_argument("unsupported ACK flags");
        packet.PDS_type=RUOD_ack_header; auto& h=packet.PDS_header.RUOD_ack_header;
        h.type=ACK; h.next_hdr=next; h.flags.m=(flags>>5)&1; h.flags.retx=(flags>>4)&1;
        h.flags.p=(flags>>3)&1; h.flags.req=(flags>>1)&3;
        h.ack_psn_off=static_cast<int16_t>(r.take(2)); h.cack_psn=r.take(4); h.spdcid=r.take(2); h.dpdcid=r.take(2);
    } else if (type==10) {
        if ((flags&0x47)||next!=UET_HDR_NONE) throw std::invalid_argument("invalid NACK flags");
        packet.PDS_type=nack_header; auto& h=packet.PDS_header.nack_header;
        h.type=NACK; h.next_hdr=next; h.flags.m=(flags>>5)&1; h.flags.retx=(flags>>4)&1; h.flags.nt=(flags>>3)&1;
        h.nack_code=static_cast<PDS_Nack_Codes>(r.take(1)); h.vendor_code=r.take(1);
        h.nack_psn=r.take(4); h.spdcid=r.take(2); h.dpdcid=r.take(2); h.payload=r.take(4);
    } else if (type==11) {
        if (flags&0x43) throw std::invalid_argument("invalid CP flags");
        packet.PDS_type=RUOD_cp_header; auto& h=packet.PDS_header.RUOD_cp_header;
        h.type=CP; h.ctl_type=(prologue>>7)&0xf;
        h.flags.isrod=(flags>>5)&1; h.flags.retx=(flags>>4)&1; h.flags.ar=(flags>>3)&1; h.flags.syn=(flags>>2)&1;
        h.probe_opaque=r.take(2); h.psn=r.take(4); h.spdcid=r.take(2);
        const auto destination=r.take(2);
        if (h.flags.syn) { h.pdc_info=destination>>12; h.psn_off=destination&0xfff; } else h.dpdcid=destination;
        h.payload=r.take(4); next=UET_HDR_NONE;
    } else throw std::invalid_argument("PDS wire format not implemented");
    get_semantic(r,packet,next);
    return packet;
}
} // namespace

uint32_t UetWireCodec::crc32c(const uint8_t* bytes, size_t length) {
    uint32_t crc=0xffffffff;
    for (size_t i=0; i<length; ++i) {
        crc ^= bytes[i];
        for (int bit=0; bit<8; ++bit) crc=(crc>>1)^((crc&1)?0x82f63b78u:0u);
    }
    return ~crc;
}
std::vector<uint8_t> UetWireCodec::encode(const PDStoNET_pkt& packet, const WireOptions& o) {
    if (o.dscp>63 || o.ecn>3 || !o.hop_limit) throw std::invalid_argument("invalid network fields");
    const auto body=encode_pds(packet);
    const size_t ip_size=o.ipv6?40:20, transport=o.udp?8:4;
    const size_t ip_length=ip_size+transport+body.size()+(o.crc?4:0);
    if (ip_length>65535) throw std::length_error("packet exceeds supported MTU");
    Bytes out; out.insert(out.end(),o.destination.mac.begin(),o.destination.mac.end());
    out.insert(out.end(),o.source.mac.begin(),o.source.mac.end()); put(out,o.ipv6?0x86dd:0x0800,2);
    const size_t ip_begin=out.size();
    if (o.ipv6) {
        put(out,(6u<<28)|((uint32_t{o.dscp}<<2|o.ecn)<<20),4);
        put(out,ip_length-40,2); put(out,o.udp?17:253,1); put(out,o.hop_limit,1);
        out.insert(out.end(),o.source.ip.begin(),o.source.ip.end()); out.insert(out.end(),o.destination.ip.begin(),o.destination.ip.end());
    } else {
        put(out,0x45,1); put(out,(o.dscp<<2)|o.ecn,1); put(out,ip_length,2);
        put(out,0,2); put(out,0x4000,2); put(out,o.hop_limit,1); put(out,o.udp?17:253,1); put(out,0,2);
        out.insert(out.end(),o.source.ip.begin(),o.source.ip.begin()+4);
        out.insert(out.end(),o.destination.ip.begin(),o.destination.ip.begin()+4);
        const auto checksum=ip_checksum(out.data()+ip_begin);
        out[ip_begin+10]=checksum>>8; out[ip_begin+11]=checksum&255;
    }
    if (o.udp) {
        put(out,o.entropy,2); put(out,49150,2); put(out,ip_length-ip_size,2); put(out,0,2);
    } else { put(out,o.entropy,2); put(out,0,2); }
    out.insert(out.end(),body.begin(),body.end());
    if (o.crc) {
        const auto start=ip_begin+(o.ipv6?8:12);
        const auto crc=crc32c(out.data()+start,out.size()-start);
        for (size_t i=0;i<4;++i) out.push_back(static_cast<uint8_t>(crc>>(8*i)));
    }
    return out;
}

DecodedPacket UetWireCodec::decode(const uint8_t* bytes, size_t size, bool crc_enabled) {
    if (!bytes || size<34) throw std::invalid_argument("truncated Ethernet/IP frame");
    DecodedPacket result;
    auto& o=result.network; o.crc=crc_enabled;
    std::copy_n(bytes,6,o.destination.mac.begin()); std::copy_n(bytes+6,6,o.source.mac.begin());
    const auto ether=get(bytes+12,2);
    if (ether!=0x0800 && ether!=0x86dd) throw std::invalid_argument("unsupported EtherType");
    o.ipv6=ether==0x86dd;
    const size_t ip_begin=14, ip_size=o.ipv6?40:20;
    if (size<ip_begin+ip_size) throw std::invalid_argument("truncated IP header");
    const auto* ip=bytes+ip_begin;
    size_t end; uint8_t protocol;
    if (o.ipv6) {
        if ((ip[0]>>4)!=6) throw std::invalid_argument("invalid IPv6 version");
        end=ip_begin+40+get(ip+4,2); protocol=ip[6]; o.hop_limit=ip[7];
        const auto traffic=static_cast<uint8_t>(get(ip,2)>>4); o.dscp=traffic>>2; o.ecn=traffic&3;
        std::copy_n(ip+8,16,o.source.ip.begin()); std::copy_n(ip+24,16,o.destination.ip.begin());
    } else {
        if (ip[0]!=0x45 || ip_checksum(ip)!=0 || (get(ip+6,2)&0xbfff)) throw std::invalid_argument("invalid or unsupported IPv4 header");
        end=ip_begin+get(ip+2,2); protocol=ip[9]; o.hop_limit=ip[8]; o.dscp=ip[1]>>2; o.ecn=ip[1]&3;
        std::copy_n(ip+12,4,o.source.ip.begin()); std::copy_n(ip+16,4,o.destination.ip.begin());
    }
    if (protocol!=17 && protocol!=253) throw std::invalid_argument("unsupported IP protocol");
    o.udp=protocol==17;
    const size_t transport=o.udp?8:4, start=ip_begin+ip_size;
    if (!o.hop_limit || end>size || end<start+transport+2+(crc_enabled?4:0))
        throw std::invalid_argument("invalid IP length or hop limit");
    o.entropy=get(bytes+start,2);
    if (o.udp) {
        if (get(bytes+start+2,2)!=49150 || get(bytes+start+4,2)!=end-start || get(bytes+start+6,2)!=0)
            throw std::invalid_argument("unsupported or invalid UET UDP header");
    } else if (get(bytes+start+2,2)!=0) throw std::invalid_argument("reserved entropy bits");
    if (crc_enabled) {
        const auto crc_start=ip_begin+(o.ipv6?8:12);
        const auto crc=crc32c(bytes+crc_start,end-crc_start-4);
        uint32_t actual=0;
        for (size_t i=0;i<4;++i) actual|=uint32_t{bytes[end-4+i]}<<(8*i);
        if (crc!=actual) throw std::invalid_argument("UET CRC mismatch");
    }
    result.packet=decode_pds(bytes+start+transport,end-start-transport-(crc_enabled?4:0));
    return result;
}

void UetWireCodec::mark_ecn(std::vector<uint8_t>& frame) {
    if (frame.size()<34) throw std::invalid_argument("truncated ECN frame");
    const auto ether=get(frame.data()+12,2);
    if (ether==0x0800) {
        frame[15]|=3; frame[24]=frame[25]=0;
        const auto checksum=ip_checksum(frame.data()+14);
        frame[24]=checksum>>8; frame[25]=checksum&255;
    } else if (ether==0x86dd) {
        if (frame.size()<54) throw std::invalid_argument("truncated IPv6 ECN frame");
        frame[15]|=0x30;
    } else throw std::invalid_argument("unsupported ECN EtherType");
}
} // namespace UET::NetworkLayer
