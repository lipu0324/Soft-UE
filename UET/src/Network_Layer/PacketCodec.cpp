#include "PacketCodec.hpp"

#include <stdexcept>

namespace UET::NetworkLayer {
namespace {

constexpr uint32_t kMagic = 0x53554531; // SUE1
constexpr uint8_t kVersion = 1;

void put16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void put32(std::vector<uint8_t>& out, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<uint8_t>(value >> shift));
}

uint16_t get16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t get32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

// CRC-32/ISO-HDLC. Checksum field (bytes 32..35) is treated as zero.
uint32_t checksum(const uint8_t* bytes, size_t size) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; ++i) {
        const uint8_t value = (i >= 32 && i < 36) ? 0 : bytes[i];
        crc ^= value;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xedb88320u : 0u);
    }
    return ~crc;
}

void validate(const MessageFrame& frame) {
    if (frame.total_length > PacketCodec::kMaxMessageSize ||
        frame.payload.size() > PacketCodec::kMaxPayloadSize ||
        frame.offset > frame.total_length ||
        frame.payload.size() > frame.total_length - frame.offset ||
        frame.message_id == 0 ||
        (frame.first && frame.offset != 0) ||
        (frame.last && frame.offset + frame.payload.size() != frame.total_length) ||
        (frame.total_length == 0 && !(frame.first && frame.last && frame.payload.empty())) ||
        (frame.total_length != 0 && frame.payload.empty()))
        throw std::invalid_argument("invalid Soft-UE message frame");
}

} // namespace

std::vector<uint8_t> PacketCodec::encode(const MessageFrame& frame) {
    validate(frame);
    std::vector<uint8_t> out;
    out.reserve(kHeaderSize + frame.payload.size());
    put32(out, kMagic);
    out.push_back(kVersion);
    out.push_back(static_cast<uint8_t>((frame.first ? 1 : 0) | (frame.last ? 2 : 0)));
    put16(out, static_cast<uint16_t>(kHeaderSize));
    put32(out, frame.src_fep);
    put32(out, frame.dst_fep);
    put32(out, frame.message_id);
    put32(out, frame.total_length);
    put32(out, frame.offset);
    put16(out, static_cast<uint16_t>(frame.payload.size()));
    put16(out, 0);
    put32(out, 0);
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    const uint32_t crc = checksum(out.data(), out.size());
    for (int i = 0; i < 4; ++i)
        out[32 + i] = static_cast<uint8_t>(crc >> (24 - 8 * i));
    return out;
}

MessageFrame PacketCodec::decode(const uint8_t* bytes, size_t size) {
    if (!bytes || size < kHeaderSize || size > kMaxFrameSize ||
        get32(bytes) != kMagic || bytes[4] != kVersion ||
        (bytes[5] & ~uint8_t{3}) != 0 || get16(bytes + 6) != kHeaderSize ||
        get16(bytes + 30) != 0 || get16(bytes + 28) != size - kHeaderSize ||
        get32(bytes + 32) != checksum(bytes, size))
        throw std::invalid_argument("invalid or corrupt Soft-UE wire frame");

    MessageFrame frame;
    frame.first = (bytes[5] & 1) != 0;
    frame.last = (bytes[5] & 2) != 0;
    frame.src_fep = get32(bytes + 8);
    frame.dst_fep = get32(bytes + 12);
    frame.message_id = get32(bytes + 16);
    frame.total_length = get32(bytes + 20);
    frame.offset = get32(bytes + 24);
    frame.payload.assign(bytes + kHeaderSize, bytes + size);
    validate(frame);
    return frame;
}

} // namespace UET::NetworkLayer
