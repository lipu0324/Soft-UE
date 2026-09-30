#pragma once

#include "../PDS/MessageStream.hpp"

#include <chrono>
#include <cstdint>
#include <vector>

namespace UET::SES {

class MessageEndpoint {
public:
    MessageEndpoint(NetworkLayer::PacketChannel& channel, uint32_t local_fep,
                    uint32_t peer_fep);

    void send(const std::vector<uint8_t>& message,
              std::chrono::milliseconds timeout = std::chrono::seconds(10));
    std::vector<uint8_t> receive(
        std::chrono::milliseconds timeout = std::chrono::seconds(10));

private:
    PDS::MessageStream stream_;
};

} // namespace UET::SES
