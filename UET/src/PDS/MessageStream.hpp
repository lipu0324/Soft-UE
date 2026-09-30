#pragma once

#include "../Network_Layer/PacketChannel.hpp"

#include <chrono>
#include <cstdint>
#include <vector>

namespace UET::PDS {

// A bounded, ordered PDS message subset. RC supplies reliable frame delivery;
// this class owns segmentation, offsets, and reassembly validation.
class MessageStream {
public:
    MessageStream(NetworkLayer::PacketChannel& channel, uint32_t local_fep,
                  uint32_t peer_fep);
    void send(const std::vector<uint8_t>& message, std::chrono::milliseconds timeout);
    std::vector<uint8_t> receive(std::chrono::milliseconds timeout);

private:
    NetworkLayer::PacketChannel& channel_;
    uint32_t local_fep_;
    uint32_t peer_fep_;
    uint32_t next_message_id_ = 1;
};

} // namespace UET::PDS
