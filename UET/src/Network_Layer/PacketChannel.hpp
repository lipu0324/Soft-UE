#pragma once

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace UET::NetworkLayer {

class PacketTimeout final : public std::runtime_error {
public:
    explicit PacketTimeout(const char* message) : std::runtime_error(message) {}
};

class PacketChannel {
public:
    virtual ~PacketChannel() = default;
    virtual void send_packet(const std::vector<uint8_t>& bytes,
                             std::chrono::milliseconds timeout) = 0;
    virtual std::vector<uint8_t> receive_packet(std::chrono::milliseconds timeout) = 0;
};

} // namespace UET::NetworkLayer
