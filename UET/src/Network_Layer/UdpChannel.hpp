#pragma once

#include "PacketChannel.hpp"

#include <netinet/in.h>

#include <cstdint>
#include <string>

namespace UET::NetworkLayer {

// Optional software transport for the same encoded frames. It has no delivery
// guarantee and is intended for functional development, not RDMA validation.
class UdpChannel final : public PacketChannel {
public:
    UdpChannel(bool server, uint16_t port, const std::string& peer_ip);
    ~UdpChannel() override;
    UdpChannel(const UdpChannel&) = delete;
    UdpChannel& operator=(const UdpChannel&) = delete;

    void send_packet(const std::vector<uint8_t>& bytes,
                     std::chrono::milliseconds timeout) override;
    std::vector<uint8_t> receive_packet(std::chrono::milliseconds timeout) override;

private:
    int fd_ = -1;
    sockaddr_in peer_{};
    bool peer_known_ = false;
};

} // namespace UET::NetworkLayer
