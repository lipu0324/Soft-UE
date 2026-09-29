#include "PdsPacketCodec.hpp"

#include <stdexcept>

namespace UET::NetworkLayer {
namespace {

constexpr uint32_t kMagic = 0x53555031; // SUP1
constexpr uint8_t kVersion = 1;
constexpr size_t kStandardHeaderSize = 50;

void put8(std::vector<uint8_t>& out, uint8_t value) { out.push_back(value); }
void put16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8)); out.push_back(static_cast<uint8_t>(value));
}
void put32(std::vector<uint8_t>& out, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(value >> shift));
}
void put64(std::vector<uint8_t>& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(value >> shift));
}
uint8_t get8(const uint8_t* p) { return p[0]; }
uint16_t get16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t get32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
uint64_t get64(const uint8_t* p) {
    uint64_t value = 0; for (int i = 0; i < 8; ++i) value = (value << 8) | p[i]; return value;
}

class Reader {
public:
    Reader(const uint8_t* data, size_t size) : data_(data), size_(size) {}
    uint8_t u8() { require(1); return get8(data_ + offset_++); }
    uint16_t u16() { require(2); const auto v = get16(data_ + offset_); offset_ += 2; return v; }
    uint32_t u32() { require(4); const auto v = get32(data_ + offset_); offset_ += 4; return v; }
    uint64_t u64() { require(8); const auto v = get64(data_ + offset_); offset_ += 8; return v; }
    std::vector<uint8_t> bytes(size_t length) {
        require(length); std::vector<uint8_t> result(data_ + offset_, data_ + offset_ + length);
        offset_ += length; return result;
    }
    size_t offset() const { return offset_; }
private:
    void require(size_t length) const {
        if (offset_ > size_ || length > size_ - offset_)
            throw std::invalid_argument("truncated PDS wire packet");
    }
    const uint8_t* data_; size_t size_; size_t offset_ = 0;
};

uint8_t req_flags(const PDS_RUOD_req_header& h) {
    return static_cast<uint8_t>((h.flags.retx << 2) | (h.flags.ar << 3) | (h.flags.syn << 4));
}
uint8_t ack_flags(const PDS_RUOD_ack_header& h) {
    return static_cast<uint8_t>((h.flags.m << 1) | (h.flags.retx << 2) |
                                (h.flags.p << 3) | ((h.flags.req & 3) << 4));
}
uint8_t cp_flags(const PDS_RUOD_cp_header& h) {
    return static_cast<uint8_t>((h.flags.isrod << 1) | (h.flags.retx << 2) |
                                (h.flags.ar << 3) | (h.flags.syn << 4));
}
uint8_t nack_flags(const PDS_nack_header& h) {
    return static_cast<uint8_t>((h.flags.m << 1) | (h.flags.retx << 2) | (h.flags.nt << 3));
}

void put_standard(std::vector<uint8_t>& out, const SES_Standard_Header& h) {
    put16(out, h.msg_id); put8(out, h.ri_generation); put32(out, h.job_id);
    put16(out, h.PIDonFEP); put16(out, h.resource_index); put64(out, h.buffer_offset);
    put32(out, h.initiator); put64(out, h.match_bits);
    put8(out, static_cast<uint8_t>((h.ie << 0) | (h.rel << 1) | (h.dc << 2) |
                                   (h.hd << 3) | (h.eom << 4) | (h.som << 5)));
    put64(out, h.diff.som_true.header_data);
    put16(out, h.diff.som_false.payload_length); put32(out, h.diff.som_false.message_offset);
    put32(out, h.request_length);
}

void get_standard(Reader& r, SES_Standard_Header& h) {
    h.msg_id = r.u16(); h.ri_generation = r.u8(); h.job_id = r.u32();
    h.PIDonFEP = r.u16(); h.resource_index = r.u16(); h.buffer_offset = r.u64();
    h.initiator = r.u32(); h.match_bits = r.u64(); const auto flags = r.u8();
    h.ie = flags & 1; h.rel = (flags >> 1) & 1; h.dc = (flags >> 2) & 1;
    h.hd = (flags >> 3) & 1; h.eom = (flags >> 4) & 1; h.som = (flags >> 5) & 1;
    h.diff.som_true.header_data = r.u64(); h.diff.som_false.payload_length = r.u16();
    h.diff.som_false.message_offset = r.u32(); h.request_length = r.u32();
}

size_t pds_wire_size(PDS_header_type type) {
    switch (type) {
    case RUOD_req_header: return 16;
    case RUOD_ack_header: return 13;
    case RUOD_cp_header: return 20;
    case nack_header: return 17;
    default: throw std::invalid_argument("unsupported PDS header type");
    }
}

void validate_standard_payload(const SES_Standard_Header& h, size_t payload_size) {
    const uint64_t offset = h.som ? 0 : h.diff.som_false.message_offset;
    const uint64_t end = offset + payload_size;
    if (end > UINT32_MAX)
        throw std::length_error("SES payload offset exceeds wire range");

    // For non-first fragments the SES header carries the exact byte count for
    // this fragment. First fragments carry the total request length instead.
    if (!h.som && h.diff.som_false.payload_length != payload_size)
        throw std::invalid_argument("SES fragment payload length mismatch");

    if (h.request_length < end)
        throw std::invalid_argument("SES payload exceeds request length");
    if (h.eom && h.request_length != end)
        throw std::invalid_argument("SES end fragment does not terminate request");
    if (h.som && h.eom && h.request_length != payload_size)
        throw std::invalid_argument("SES single fragment length mismatch");
}

} // namespace

std::vector<uint8_t> PdsPacketCodec::encode(const PDStoNET_pkt& packet) {
    if (packet.SESpkt.bth_type != Standard_Header)
        throw std::invalid_argument("only SES standard headers are supported");
    std::vector<uint8_t> out;
    out.reserve(160 + packet.SESpkt.payload.size());
    put32(out, kMagic); put8(out, kVersion); put8(out, static_cast<uint8_t>(packet.PDS_type));
    put8(out, static_cast<uint8_t>(packet.SESpkt.bth_type)); put8(out, 0);
    put32(out, packet.src_fep); put32(out, packet.dst_fep);
    const size_t header_size_offset = out.size(); put16(out, 0); put16(out, 0);
    const size_t payload_size_offset = out.size(); put32(out, 0);
    const size_t pds_begin = out.size();
    switch (packet.PDS_type) {
    case RUOD_req_header: {
        const auto& h = packet.PDS_header.RUOD_req_header;
        put8(out, static_cast<uint8_t>(h.type)); put8(out, static_cast<uint8_t>(h.next_hdr)); put8(out, req_flags(h));
        put16(out, h.clear_psn_off); put32(out, h.psn); put16(out, h.spdcid); put16(out, h.dpdcid);
        put8(out, static_cast<uint8_t>(h.pdc_info)); put16(out, static_cast<uint16_t>(h.psn_off)); break;
    }
    case RUOD_ack_header: {
        const auto& h = packet.PDS_header.RUOD_ack_header;
        put8(out, static_cast<uint8_t>(h.type)); put8(out, static_cast<uint8_t>(h.next_hdr)); put8(out, ack_flags(h));
        put16(out, static_cast<uint16_t>(h.ack_psn_off)); put32(out, h.cack_psn); put16(out, h.spdcid); put16(out, h.dpdcid); break;
    }
    case RUOD_cp_header: {
        const auto& h = packet.PDS_header.RUOD_cp_header;
        put8(out, static_cast<uint8_t>(h.type)); put8(out, h.ctl_type); put8(out, cp_flags(h));
        put16(out, h.probe_opaque); put32(out, h.psn); put16(out, h.spdcid); put16(out, h.dpdcid);
        put8(out, static_cast<uint8_t>(h.pdc_info)); put16(out, static_cast<uint16_t>(h.psn_off)); put32(out, h.payload); break;
    }
    case nack_header: {
        const auto& h = packet.PDS_header.nack_header;
        put8(out, static_cast<uint8_t>(h.type)); put8(out, static_cast<uint8_t>(h.next_hdr)); put8(out, nack_flags(h));
        put8(out, static_cast<uint8_t>(h.nack_code)); put8(out, h.vendor_code); put32(out, h.nack_psn);
        put16(out, h.spdcid); put16(out, h.dpdcid); put32(out, h.payload); break;
    }
    default: throw std::invalid_argument("unsupported PDS header type");
    }
    const uint16_t pds_size = static_cast<uint16_t>(out.size() - pds_begin);
    const size_t ses_begin = out.size(); put_standard(out, packet.SESpkt.bth_header.Standard_Header);
    const uint16_t ses_size = static_cast<uint16_t>(out.size() - ses_begin);
    validate_standard_payload(packet.SESpkt.bth_header.Standard_Header,
                              packet.SESpkt.payload.size());
    if (out.size() > PdsPacketCodec::kMaxPacketSize ||
        packet.SESpkt.payload.size() > PdsPacketCodec::kMaxPacketSize - out.size())
        throw std::length_error("PDS packet exceeds RDMA frame size");
    out.insert(out.end(), packet.SESpkt.payload.begin(), packet.SESpkt.payload.end());
    const uint32_t payload_size = static_cast<uint32_t>(packet.SESpkt.payload.size());
    out[header_size_offset] = static_cast<uint8_t>(pds_size >> 8); out[header_size_offset + 1] = static_cast<uint8_t>(pds_size);
    out[header_size_offset + 2] = static_cast<uint8_t>(ses_size >> 8); out[header_size_offset + 3] = static_cast<uint8_t>(ses_size);
    for (int i = 0; i < 4; ++i) out[payload_size_offset + i] = static_cast<uint8_t>(payload_size >> (24 - i * 8));
    return out;
}

PDStoNET_pkt PdsPacketCodec::decode(const uint8_t* bytes, size_t size) {
    if (!bytes || size < 16 || size > kMaxPacketSize) throw std::invalid_argument("invalid PDS wire packet");
    Reader r(bytes, size);
    if (r.u32() != kMagic || r.u8() != kVersion) throw std::invalid_argument("PDS wire magic/version mismatch");
    const auto pds_type = r.u8(); const auto bth_type = r.u8();
    if (r.u8() != 0) throw std::invalid_argument("PDS wire reserved byte is nonzero");
    if (bth_type != Standard_Header) throw std::invalid_argument("unsupported SES header type");
    PDStoNET_pkt packet{}; packet.PDS_type = static_cast<PDS_header_type>(pds_type);
    packet.src_fep = r.u32(); packet.dst_fep = r.u32(); const auto pds_size = r.u16(); const auto ses_size = r.u16(); const auto payload_size = r.u32();
    const size_t header_start = r.offset();
    if (pds_size != pds_wire_size(packet.PDS_type) || ses_size != kStandardHeaderSize ||
        header_start + pds_size + ses_size + payload_size != size ||
        pds_size == 0 || ses_size == 0)
        throw std::invalid_argument("PDS wire lengths are inconsistent");
    switch (packet.PDS_type) {
    case RUOD_req_header: { auto& h = packet.PDS_header.RUOD_req_header; h.type = static_cast<PDS_type>(r.u8()); h.next_hdr = static_cast<PDS_next_hdr>(r.u8()); const auto f=r.u8(); h.flags.retx=(f>>2)&1; h.flags.ar=(f>>3)&1; h.flags.syn=(f>>4)&1; h.clear_psn_off=r.u16(); h.psn=r.u32(); h.spdcid=r.u16(); h.dpdcid=r.u16(); h.pdc_info=r.u8(); h.psn_off=r.u16(); break; }
    case RUOD_ack_header: { auto& h = packet.PDS_header.RUOD_ack_header; h.type = static_cast<PDS_type>(r.u8()); h.next_hdr = static_cast<PDS_next_hdr>(r.u8()); const auto f=r.u8(); h.flags.m=(f>>1)&1; h.flags.retx=(f>>2)&1; h.flags.p=(f>>3)&1; h.flags.req=(f>>4)&3; h.ack_psn_off=static_cast<int16_t>(r.u16()); h.cack_psn=r.u32(); h.spdcid=r.u16(); h.dpdcid=r.u16(); break; }
    case RUOD_cp_header: { auto& h = packet.PDS_header.RUOD_cp_header; h.type = static_cast<PDS_type>(r.u8()); h.ctl_type=r.u8(); const auto f=r.u8(); h.flags.isrod=(f>>1)&1; h.flags.retx=(f>>2)&1; h.flags.ar=(f>>3)&1; h.flags.syn=(f>>4)&1; h.probe_opaque=r.u16(); h.psn=r.u32(); h.spdcid=r.u16(); h.dpdcid=r.u16(); h.pdc_info=r.u8(); h.psn_off=r.u16(); h.payload=r.u32(); break; }
    case nack_header: { auto& h = packet.PDS_header.nack_header; h.type = static_cast<PDS_type>(r.u8()); h.next_hdr=static_cast<PDS_next_hdr>(r.u8()); const auto f=r.u8(); h.flags.m=(f>>1)&1; h.flags.retx=(f>>2)&1; h.flags.nt=(f>>3)&1; h.nack_code=static_cast<PDS_Nack_Codes>(r.u8()); h.vendor_code=r.u8(); h.nack_psn=r.u32(); h.spdcid=r.u16(); h.dpdcid=r.u16(); h.payload=r.u32(); break; }
    default: throw std::invalid_argument("unsupported PDS header type");
    }
    if (r.offset() != header_start + pds_size) throw std::invalid_argument("PDS header length mismatch");
    packet.SESpkt.bth_type = Standard_Header; get_standard(r, packet.SESpkt.bth_header.Standard_Header);
    if (r.offset() != header_start + pds_size + ses_size) throw std::invalid_argument("SES header length mismatch");
    packet.SESpkt.payload = r.bytes(payload_size);
    validate_standard_payload(packet.SESpkt.bth_header.Standard_Header,
                              packet.SESpkt.payload.size());
    return packet;
}

} // namespace UET::NetworkLayer
