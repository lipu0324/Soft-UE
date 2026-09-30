#include "MessageStream.hpp"

#include "../Network_Layer/PacketCodec.hpp"

#include <algorithm>
#include <stdexcept>

namespace UET::PDS {

MessageStream::MessageStream(NetworkLayer::PacketChannel& channel, uint32_t local_fep,
                             uint32_t peer_fep)
    : channel_(channel), local_fep_(local_fep), peer_fep_(peer_fep) {}

void MessageStream::send(const std::vector<uint8_t>& message,
                         std::chrono::milliseconds timeout) {
    if (message.size() > NetworkLayer::PacketCodec::kMaxMessageSize)
        throw std::length_error("message exceeds the configured maximum");
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    const uint32_t id = next_message_id_++;
    if (next_message_id_ == 0) next_message_id_ = 1;

    size_t offset = 0;
    do {
        const size_t length = std::min(message.size() - offset,
                                       NetworkLayer::PacketCodec::kMaxPayloadSize);
        NetworkLayer::MessageFrame frame;
        frame.src_fep = local_fep_;
        frame.dst_fep = peer_fep_;
        frame.message_id = id;
        frame.total_length = static_cast<uint32_t>(message.size());
        frame.offset = static_cast<uint32_t>(offset);
        frame.first = offset == 0;
        frame.last = offset + length == message.size();
        frame.payload.assign(message.begin() + offset, message.begin() + offset + length);
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) throw std::runtime_error("message send timed out");
        channel_.send_packet(NetworkLayer::PacketCodec::encode(frame), remaining);
        offset += length;
    } while (offset < message.size());
}

std::vector<uint8_t> MessageStream::receive(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<uint8_t> message;
    uint32_t active_id = 0;
    uint32_t expected_length = 0;
    for (;;) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) throw std::runtime_error("message receive timed out");
        const auto bytes = channel_.receive_packet(remaining);
        const auto frame = NetworkLayer::PacketCodec::decode(bytes.data(), bytes.size());
        if (frame.src_fep != peer_fep_ || frame.dst_fep != local_fep_)
            throw std::runtime_error("message FEP does not match connection");
        if (active_id == 0) {
            if (!frame.first) throw std::runtime_error("first fragment missing");
            active_id = frame.message_id;
            expected_length = frame.total_length;
            message.reserve(expected_length);
        } else if (frame.first || frame.message_id != active_id ||
                   frame.total_length != expected_length) {
            throw std::runtime_error("interleaved or inconsistent message fragments");
        }
        if (frame.offset != message.size())
            throw std::runtime_error("message fragment gap or duplicate");
        message.insert(message.end(), frame.payload.begin(), frame.payload.end());
        if (frame.last) return message;
        if (message.size() == expected_length)
            throw std::runtime_error("message ended without last flag");
    }
}

} // namespace UET::PDS
