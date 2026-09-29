#include "PdsQueueTransport.hpp"

#include <stdexcept>
#include <utility>

namespace UET::NetworkLayer {

bool PdsQueueTransport::pump_outbound(std::chrono::milliseconds timeout) {
    PDStoNET_pkt packet{};
    // Encode a copy first, so an invalid packet does not disappear from the
    // queue. The pump is intended to have one consumer.
    if (!outbound_.front(packet)) return false;
    channel_.send_packet(PdsPacketCodec::encode(packet), timeout);
    if (!outbound_.pop(packet))
        throw std::runtime_error("PDS outbound queue changed during pump");
    return true;
}

bool PdsQueueTransport::pump_inbound(std::chrono::milliseconds timeout) {
    const auto bytes = channel_.receive_packet(timeout);
    auto packet = PdsPacketCodec::decode(bytes.data(), bytes.size());
    if (!inbound_.push(std::move(packet)))
        throw std::runtime_error("PDS inbound queue is full or shut down");
    return true;
}

size_t PdsQueueTransport::progress(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    size_t progressed = 0;
    if (!outbound_.empty()) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) throw PacketTimeout("PDS progress timed out before send");
        pump_outbound(remaining);
        ++progressed;
    }

    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    try {
        if (remaining.count() > 0 && pump_inbound(remaining)) ++progressed;
    } catch (const PacketTimeout&) {
        // A quiet receive side is normal for a shared progress loop.
    }
    return progressed;
}

} // namespace UET::NetworkLayer
