#include "UdpChannel.hpp"

#include "PacketCodec.hpp"
#include "PdsPacketCodec.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <stdexcept>

namespace UET::NetworkLayer {

UdpChannel::UdpChannel(bool server, uint16_t port, const std::string& peer_ip) {
    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) throw std::runtime_error("UDP socket failed");
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(server ? port : 0);
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        ::close(fd_); fd_ = -1;
        throw std::runtime_error("UDP bind failed");
    }
    if (!server) {
        peer_.sin_family = AF_INET;
        peer_.sin_port = htons(port);
        if (::inet_pton(AF_INET, peer_ip.c_str(), &peer_.sin_addr) != 1) {
            ::close(fd_); fd_ = -1;
            throw std::invalid_argument("UDP peer must be an IPv4 address");
        }
        peer_known_ = true;
    }
}

UdpChannel::~UdpChannel() { if (fd_ >= 0) ::close(fd_); }

void UdpChannel::send_packet(const std::vector<uint8_t>& bytes,
                             std::chrono::milliseconds timeout) {
    if (bytes.empty() || bytes.size() > PdsPacketCodec::kMaxPacketSize)
        throw std::invalid_argument("invalid UDP packet");
    if (!peer_known_)
        throw PacketTimeout("UDP peer is not known yet");
    pollfd ready{fd_, POLLOUT, 0};
    if (::poll(&ready, 1, static_cast<int>(timeout.count())) != 1 ||
        !(ready.revents & POLLOUT))
        throw PacketTimeout("UDP send timed out");
    const ssize_t sent = ::sendto(fd_, bytes.data(), bytes.size(), 0,
                                  reinterpret_cast<sockaddr*>(&peer_), sizeof(peer_));
    if (sent != static_cast<ssize_t>(bytes.size()))
        throw std::runtime_error("UDP send failed");
}

std::vector<uint8_t> UdpChannel::receive_packet(std::chrono::milliseconds timeout) {
    pollfd ready{fd_, POLLIN, 0};
    if (::poll(&ready, 1, static_cast<int>(timeout.count())) != 1 ||
        !(ready.revents & POLLIN))
        throw PacketTimeout("UDP receive timed out");
    std::array<uint8_t, PdsPacketCodec::kMaxPacketSize + 1> bytes{};
    sockaddr_in sender{};
    socklen_t sender_size = sizeof(sender);
    const ssize_t length = ::recvfrom(fd_, bytes.data(), bytes.size(), 0,
                                      reinterpret_cast<sockaddr*>(&sender), &sender_size);
    if (length <= 0 || length > static_cast<ssize_t>(PdsPacketCodec::kMaxPacketSize))
        throw std::runtime_error("invalid UDP datagram length");
    if (peer_known_) {
        if (sender.sin_addr.s_addr != peer_.sin_addr.s_addr ||
            sender.sin_port != peer_.sin_port)
            throw std::runtime_error("UDP packet from unexpected peer");
    } else {
        peer_ = sender;
        peer_known_ = true;
    }
    return std::vector<uint8_t>(bytes.begin(), bytes.begin() + length);
}

} // namespace UET::NetworkLayer
