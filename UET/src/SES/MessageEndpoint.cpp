#include "MessageEndpoint.hpp"

namespace UET::SES {

MessageEndpoint::MessageEndpoint(NetworkLayer::PacketChannel& channel,
                                 uint32_t local_fep, uint32_t peer_fep)
    : stream_(channel, local_fep, peer_fep) {}

void MessageEndpoint::send(const std::vector<uint8_t>& message,
                           std::chrono::milliseconds timeout) {
    stream_.send(message, timeout);
}

std::vector<uint8_t> MessageEndpoint::receive(std::chrono::milliseconds timeout) {
    return stream_.receive(timeout);
}

} // namespace UET::SES
