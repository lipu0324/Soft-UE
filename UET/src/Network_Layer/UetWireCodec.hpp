#pragma once
#include "../Transport_Layer.hpp"
#include "PacketTrimming.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

namespace UET::NetworkLayer {

constexpr uint16_t kDefaultUetUdpDestinationPort=4793; // UE 1.1 Table 3-35.

struct WireAddress {
    std::array<uint8_t,6> mac{};
    std::array<uint8_t,16> ip{}; // IPv4 uses the first four bytes.
};
struct WireOptions {
    WireAddress source, destination;
    bool ipv6 = false;
    bool udp = true; // Table 3-35 reference transport: UDP, destination 4793.
    bool crc = true; // Fabric-wide UET_Data_Protect setting, never autodetected.
    uint16_t entropy = 0;
    uint16_t udp_destination_port=kDefaultUetUdpDestinationPort;
    uint8_t dscp = 0;
    uint8_t ecn = 0;
    uint8_t hop_limit = 64;
    // No native UET protocol number is assigned in UE 1.1. Require an
    // explicit fabric setting when selecting native IP; zero is a valid
    // configured value and therefore cannot serve as an "unset" sentinel.
    std::optional<uint8_t> native_ip_protocol;
};
struct DecodedPacket {
    WireOptions network;
    PDStoNET_pkt packet{};
    uint32_t nominal_packet_size=0; // transport_pktsize+40, §3.6.12.2.
};

// Typed ingress errors preserve the mandatory silent-drop diagnostics without
// parsing exception strings. Known but unimplemented formats and corrupt
// packets remain ordinary invalid_argument errors, not unknown wire types.
class PdsDecodeError : public std::invalid_argument {
public:
    enum class Reason { UnknownType, UnknownControlType };
    PdsDecodeError(Reason reason,uint8_t value)
        : std::invalid_argument(reason==Reason::UnknownType?"unknown PDS type":"unknown PDS control type"),
          reason_(reason),value_(value) {}
    Reason reason() const { return reason_; }
    uint8_t value() const { return value_; }
private:
    Reason reason_;
    uint8_t value_;
};

// Initial supported subset: RUD/ROD requests, ACK, NACK, CP; standard SES
// requests and semantic responses (with/without data). Opcodes are standard
// on this interface; callers must explicitly translate legacy OpType values.
class UetWireCodec {
public:
    static uint32_t crc32c(const uint8_t* bytes, size_t length);
    static std::vector<uint8_t> encode(const PDStoNET_pkt& packet, const WireOptions& options);
    static DecodedPacket decode(const uint8_t* bytes, size_t size, bool crc_enabled = true,
                                std::optional<uint8_t> native_ip_protocol={},std::optional<TrimmingOptions> trimming={},
                                uint16_t udp_destination_port=kDefaultUetUdpDestinationPort,
                                std::optional<bool> udp_encapsulation={});
    static bool mark_ecn(std::vector<uint8_t>& frame); // Only ECT(0/1) transitions to CE.
    static bool trim_packet(std::vector<uint8_t>& frame,const TrimmingOptions& options,bool last_hop=false);
    static std::optional<uint8_t> packet_dscp(const std::vector<uint8_t>& frame);
    // NIC-only plaintext ACK_CC stamp. Preserves all unrelated bytes, including
    // UDP checksum/padding; an invalid or trimmed packet is never reconstituted.
    static bool stamp_service_time(std::vector<uint8_t>& frame,uint64_t departure_ns,uint64_t arrival_ns,
                                   bool crc_enabled,std::optional<uint8_t> native_ip_protocol={},
                                   uint16_t udp_destination_port=kDefaultUetUdpDestinationPort,
                                   std::optional<bool> udp_encapsulation={});
};
} // namespace UET::NetworkLayer
