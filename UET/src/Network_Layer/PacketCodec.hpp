#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace UET::NetworkLayer {

// Stable host-independent envelope for one PDS packet carrying SES message data.
// This is the first functional message subset, not a complete UEC wire encoding.
struct MessageFrame {
    uint32_t src_fep = 0;
    uint32_t dst_fep = 0;
    uint32_t message_id = 0;
    uint32_t total_length = 0;
    uint32_t offset = 0;
    bool first = false;
    bool last = false;
    std::vector<uint8_t> payload;
};

class PacketCodec {
public:
    static constexpr size_t kHeaderSize = 36;
    static constexpr size_t kMaxFrameSize = 4096;
    static constexpr size_t kMaxPayloadSize = kMaxFrameSize - kHeaderSize;
    static constexpr uint32_t kMaxMessageSize = 1024 * 1024;

    static std::vector<uint8_t> encode(const MessageFrame& frame);
    static MessageFrame decode(const uint8_t* bytes, size_t size);
};

} // namespace UET::NetworkLayer
