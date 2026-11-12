#pragma once
#include "PacketPort.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <map>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/socket.h>
#include <unistd.h>

namespace UET::Runtime {

// An unprivileged real-time adapter. Each UDP payload is an unchanged Ethernet
// frame, including the UE headers and CRC. This outer tunnel is an experiment
// transport, distinct from the standard UET-over-UDP header inside that frame.
// It adds no acknowledgements, ordering, retry or peer-memory access of its own.
class UdpFramePort final : public IPacketPort {
public:
    explicit UdpFramePort(uint32_t node,uint16_t port=0,const std::string& bind_ip="127.0.0.1") : node_(node) {
        const auto local=address(bind_ip,port);
        socket_=::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        if (socket_<0) throw std::system_error(errno,std::generic_category(),"UDP frame socket");
        if (::bind(socket_,reinterpret_cast<const sockaddr*>(&local),sizeof(local))<0) {
            const auto error=errno; close();
            throw std::system_error(error,std::generic_category(),"UDP frame bind");
        }
        sockaddr_in bound{}; socklen_t length=sizeof(bound);
        if (::getsockname(socket_,reinterpret_cast<sockaddr*>(&bound),&length)<0) {
            const auto error=errno; close();
            throw std::system_error(error,std::generic_category(),"UDP frame local address");
        }
        local_port_=ntohs(bound.sin_port);
        // Optional local adapter policy: use the bound UDP port as a stable
        // node number for this port's lifetime. This is not UE address discovery.
        if (!node_) node_=local_port_;
    }
    ~UdpFramePort() override { close(); }
    UdpFramePort(const UdpFramePort&)=delete;
    UdpFramePort& operator=(const UdpFramePort&)=delete;
    uint16_t local_port() const { return local_port_; }
    uint32_t node() const { return node_; }
    int descriptor() const { return socket_; }
    void add_peer(uint32_t node,const std::string& ip,uint16_t port) {
        if (!node || node==node_ || !port) throw std::invalid_argument("invalid UDP frame peer");
        const auto remote=address(ip,port);
        if (const auto existing=peers_.find(node);existing!=peers_.end() && !same_address(existing->second,remote))
            throw std::invalid_argument("node already maps to a different UDP frame peer");
        for (const auto& peer:peers_)
            if (peer.first!=node && same_address(peer.second,remote))
                throw std::invalid_argument("ambiguous UDP frame peer");
        peers_[node]=remote;
    }
    SendResult try_send(const Frame& frame) override {
        if (socket_<0) return SendResult::Closed;
        if (frame.source==node_ && frame.destination==node_) {
            if (receiver_) receiver_(frame); // Receiver enqueues work; PdsHost never re-enters PDS here.
            return SendResult::Accepted;
        }
        const auto peer=peers_.find(frame.destination);
        if (frame.source!=node_ || peer==peers_.end()) return SendResult::NoRoute;
        if (frame.bytes.size()>kMaximumDatagram) return SendResult::TooLarge;
        const auto sent=::sendto(socket_,frame.bytes.data(),frame.bytes.size(),MSG_DONTWAIT,
            reinterpret_cast<const sockaddr*>(&peer->second),sizeof(peer->second));
        if (sent<0) {
            if (errno==EAGAIN || errno==EWOULDBLOCK || errno==ENOBUFS || errno==EINTR) {
                waiting_for_write_=true; return SendResult::WouldBlock;
            }
            if (errno==EMSGSIZE) return SendResult::TooLarge;
            return SendResult::NoRoute;
        }
        return static_cast<size_t>(sent)==frame.bytes.size()?SendResult::Accepted:SendResult::NoRoute;
    }
    void set_receiver(Receiver receiver) override { receiver_=std::move(receiver); }
    void set_writable_handler(Writable callback) override { writable_=std::move(callback); }

    // Called by the application/provider's manual progress loop. Readiness
    // callbacks run on this same thread; no background thread owns the kernel.
    size_t progress(size_t packet_budget=64) {
        if (socket_<0) return 0;
        pollfd readiness{socket_,static_cast<short>(POLLIN|(waiting_for_write_?POLLOUT:0)),0};
        if (::poll(&readiness,1,0)<=0) return 0;
        if (waiting_for_write_ && (readiness.revents&POLLOUT)) {
            waiting_for_write_=false;
            if (writable_) writable_();
        }
        size_t processed=0;
        while (socket_>=0 && processed<packet_budget && (readiness.revents&POLLIN)) {
            Frame frame; frame.bytes.resize(kMaximumDatagram);
            sockaddr_in remote{}; socklen_t remote_length=sizeof(remote);
            const auto received=::recvfrom(socket_,frame.bytes.data(),frame.bytes.size(),MSG_DONTWAIT|MSG_TRUNC,
                reinterpret_cast<sockaddr*>(&remote),&remote_length);
            if (received<0) {
                if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) break;
                throw std::system_error(errno,std::generic_category(),"UDP frame receive");
            }
            ++processed;
            if (static_cast<size_t>(received)>kMaximumDatagram || remote_length!=sizeof(remote)) { ++discarded_; continue; }
            uint32_t source=0;
            for (const auto& peer:peers_) if (same_address(peer.second,remote)) { source=peer.first; break; }
            if (!source) { ++discarded_; continue; }
            frame.source=source; frame.destination=node_;
            frame.bytes.resize(static_cast<size_t>(received));
            if (receiver_) receiver_(std::move(frame));
        }
        return processed;
    }
    uint64_t discarded_datagrams() const { return discarded_; }
    void close() {
        if (socket_>=0) ::close(socket_);
        socket_=-1; waiting_for_write_=false;
        receiver_={}; writable_={};
    }
private:
    static constexpr size_t kMaximumDatagram=65507;
    uint32_t node_;
    int socket_=-1;
    uint16_t local_port_=0;
    std::map<uint32_t,sockaddr_in> peers_;
    Receiver receiver_;
    Writable writable_;
    bool waiting_for_write_=false;
    uint64_t discarded_=0;
    static sockaddr_in address(const std::string& ip,uint16_t port) {
        sockaddr_in result{}; result.sin_family=AF_INET; result.sin_port=htons(port);
        if (::inet_pton(AF_INET,ip.c_str(),&result.sin_addr)!=1) throw std::invalid_argument("invalid numeric IPv4 socket address");
        return result;
    }
    static bool same_address(const sockaddr_in& left,const sockaddr_in& right) {
        return left.sin_family==right.sin_family && left.sin_port==right.sin_port && left.sin_addr.s_addr==right.sin_addr.s_addr;
    }
};
} // namespace UET::Runtime
