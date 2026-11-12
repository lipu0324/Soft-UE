#pragma once
#include "Runtime.hpp"
#include "PacketPort.hpp"
#include "../Network_Layer/PdsPacketCodec.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include "../PDS/PDS_Manager/process/PDSProcessManager.hpp"
#include <deque>

namespace UET::Runtime {

// Runs the existing Soft-UE PDS_Manager/IPDC/TPDC, rather than a second PDS.
// The legacy wire codec is explicit until the standard codec is selected.
class PdsHost {
public:
    enum class WireFormat { Uet11, LegacySup1 };
    PdsHost(uint32_t node, EventLoop& loop, Trace& trace, IPacketPort& port,
            WireFormat format = WireFormat::Uet11,
            NetworkLayer::WireOptions network = {})
        : node_(node), loop_(loop), trace_(trace), port_(port),
          services_{loop, loop, [this] { wake(); }}, manager_(&services_), format_(format), network_(network) {
        if (!manager_.start()) throw std::runtime_error("PDS initialization failed");
        std::weak_ptr<int> life = lifetime_;
        port_.set_writable_handler([this, life] { if (!life.expired()) wake(); });
        port_.set_receiver([this, life](Frame frame) {
            if (life.expired() || stopped_) return;
            try {
                PDStoNET_pkt packet{};
                if (format_ == WireFormat::LegacySup1)
                    packet = NetworkLayer::PdsPacketCodec::decode(frame.bytes.data(), frame.bytes.size());
                else {
                    auto decoded = NetworkLayer::UetWireCodec::decode(frame.bytes.data(), frame.bytes.size(),network_.crc);
                    if (decoded.network.ipv6 != network_.ipv6 || decoded.network.udp != network_.udp ||
                        decoded.network.source.ip != address(frame.source).ip ||
                        decoded.network.destination.ip != address(node_).ip)
                        throw std::invalid_argument("network address or encapsulation mismatch");
                    packet = std::move(decoded.packet);
                    packet.src_fep=frame.source; packet.dst_fep=frame.destination;
                }
                if (packet.dst_fep != node_ || packet.src_fep != frame.source)
                    throw std::invalid_argument("frame and packet addressing disagree");
                if (!manager_.pushNetworkPacket(packet)) throw std::runtime_error("PDS inbound queue rejected frame");
                trace_.record(node_, "pds_rx", static_cast<uint64_t>(packet.PDS_type));
                wake();
            } catch (const std::invalid_argument&) { trace_.record(node_, "malformed_frame"); }
        });
    }
    ~PdsHost() { close(); }
    PdsHost(const PdsHost&) = delete;
    PdsHost& operator=(const PdsHost&) = delete;

    PDSProcessManager& manager() { return manager_; }
    void set_request_handler(std::function<void(const PDC_SES_req&)> callback) { request_handler_ = std::move(callback); }
    void set_response_handler(std::function<void(const PDC_SES_rsp&)> callback) { response_handler_ = std::move(callback); }
    bool submit(const SES_PDS_req& request) {
        if (stopped_ || request.src_fep != node_) return false;
        if (!manager_.pushSESRequest(request)) return false;
        trace_.record(node_, "ses_submit", request.tx_pkt_handle);
        wake();
        return true;
    }
    void wake() {
        if (stopped_ || pending_) return;
        std::weak_ptr<int> life = lifetime_;
        pending_ = loop_.at(loop_.now(), [this, life] {
            if (life.expired()) return;
            pending_ = 0;
            pump();
        });
    }
    void close() {
        if (stopped_) return;
        stopped_ = true;
        lifetime_.reset();
        if (pending_) loop_.cancel(pending_);
        pending_ = 0;
        port_.set_receiver({});
        port_.set_writable_handler({});
        manager_.stop(); // Destroys PDCs and cancels their virtual timers.
        outbound_.clear();
        trace_.record(node_, "host_closed");
    }
private:
    uint32_t node_;
    EventLoop& loop_;
    Trace& trace_;
    IPacketPort& port_;
    Services services_;
    PDSProcessManager manager_;
    std::shared_ptr<int> lifetime_ = std::make_shared<int>(0);
    TimerId pending_ = 0;
    bool stopped_ = false;
    std::deque<Frame> outbound_;
    std::function<void(const PDC_SES_req&)> request_handler_;
    std::function<void(const PDC_SES_rsp&)> response_handler_;
    WireFormat format_;
    NetworkLayer::WireOptions network_;

    NetworkLayer::WireAddress address(uint32_t node) const {
        NetworkLayer::WireAddress result;
        result.mac[0]=2;
        if (network_.ipv6) { result.ip[0]=0xfd; }
        const auto offset=network_.ipv6?12:0;
        for (size_t i=0; i<4; ++i) {
            const auto value=static_cast<uint8_t>(node >> (24-8*i));
            result.ip[offset+i]=value; result.mac[2+i]=value;
        }
        return result;
    }

    void pump() {
        for (size_t step=0; step<256; ++step) {
            bool worked = manager_.progressOne();
            PDStoNET_pkt packet{};
            while (manager_.popNetworkPacket(packet)) {
                Frame frame;
                frame.source = packet.src_fep;
                frame.destination = packet.dst_fep;
                if (format_ == WireFormat::LegacySup1)
                    frame.bytes = NetworkLayer::PdsPacketCodec::encode(packet);
                else {
                    auto options=network_;
                    options.source=address(packet.src_fep); options.destination=address(packet.dst_fep);
                    frame.bytes=NetworkLayer::UetWireCodec::encode(packet,options);
                }
                outbound_.push_back(std::move(frame));
                trace_.record(node_, "pds_tx", static_cast<uint64_t>(packet.PDS_type));
                worked = true;
            }
            while (!outbound_.empty()) {
                const auto result = port_.try_send(outbound_.front());
                if (result == SendResult::WouldBlock) {
                    // No busy polling: external adapters call wake() when writable.
                    return;
                }
                if (result != SendResult::Accepted) trace_.record(node_, "port_drop", static_cast<uint64_t>(result));
                outbound_.pop_front();
            }
            if (request_handler_) {
                PDC_SES_req request{};
                while (manager_.popSESRequest(request)) {
                    trace_.record(node_, "ses_request", request.orig_psn);
                    request_handler_(request);
                    if (stopped_) return;
                    worked = true;
                }
            }
            if (response_handler_) {
                PDC_SES_rsp response{};
                while (manager_.popSESResponse(response)) {
                    trace_.record(node_, "ses_response");
                    response_handler_(response);
                    if (stopped_) return;
                    worked = true;
                }
            }
            if (!worked) return;
        }
        // Yield fairly to other hosts at the same simulated instant. The event
        // budget detects a non-quiescing legacy state machine instead of hanging.
        wake();
    }
};
} // namespace UET::Runtime
