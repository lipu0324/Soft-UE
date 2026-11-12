#pragma once
#include "../Transport_Layer.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace UET::NetworkLayer {

struct WireAddress {
    std::array<uint8_t,6> mac{};
    std::array<uint8_t,16> ip{}; // IPv4 uses the first four bytes.
};
struct WireOptions {
    WireAddress source, destination;
    bool ipv6 = false;
    bool udp = false;
    bool crc = true; // Fabric-wide UET_Data_Protect setting, never autodetected.
    uint16_t entropy = 0;
    uint8_t dscp = 0;
    uint8_t ecn = 0;
    uint8_t hop_limit = 64;
};
struct DecodedPacket {
    WireOptions network;
    PDStoNET_pkt packet{};
};

// Initial supported subset: RUD/ROD requests, ACK, NACK, CP; standard SES
// requests and semantic responses (with/without data). Opcodes are standard
// on this interface; callers must explicitly translate legacy OpType values.
class UetWireCodec {
public:
    static uint32_t crc32c(const uint8_t* bytes, size_t length);
    static std::vector<uint8_t> encode(const PDStoNET_pkt& packet, const WireOptions& options);
    static DecodedPacket decode(const uint8_t* bytes, size_t size, bool crc_enabled = true);
    static void mark_ecn(std::vector<uint8_t>& frame);
};
} // namespace UET::NetworkLayer
