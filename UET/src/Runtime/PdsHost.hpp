#pragma once
#include "Runtime.hpp"
#include "PacketPort.hpp"
#include "../Network_Layer/PdsPacketCodec.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include "../CMS/NsccEngine.hpp"
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
        services_.standard_wire=format_==WireFormat::Uet11;
        services_.default_wire_entropy=network_.entropy;
        services_.actual_transmit_notifications=port_.provides_transmit_timing();
        services_.pdc_event=[this](const PdcEvent& event) { context_events_.push_back(event); };
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
                    auto decoded = NetworkLayer::UetWireCodec::decode(frame.bytes.data(), frame.bytes.size(),
                        network_.crc,network_.native_ip_protocol,trimming_);
                    if (decoded.network.ipv6 != network_.ipv6 || decoded.network.udp != network_.udp ||
                        decoded.network.source.ip != address(frame.source).ip ||
                        decoded.network.destination.ip != address(node_).ip)
                        throw std::invalid_argument("network address or encapsulation mismatch");
                    packet = std::move(decoded.packet);
                    packet.wire_entropy=decoded.network.entropy; packet.network_ecn=decoded.network.ecn;
                    packet.receive_time_ns=frame.has_arrival_timestamp?frame.first_byte_arrival_ns:loop_.now();
                    packet.has_receive_timestamp=true;
                    packet.nominal_packet_size=decoded.nominal_packet_size;
                    packet.src_fep=frame.source; packet.dst_fep=frame.destination;
                }
                if (packet.dst_fep != node_ || packet.src_fep != frame.source)
                    throw std::invalid_argument("frame and packet addressing disagree");
                if (!manager_.pushNetworkPacket(packet)) throw std::runtime_error("PDS inbound queue rejected frame");
                trace_.record(node_, "pds_rx", static_cast<uint64_t>(packet.PDS_type));
                if (packet.trimmed) trace_.record(node_,"trimmed_rx",packet.trimmed_last_hop?2:1);
                if (packet.PDS_type==nack_header)
                    trace_.record(node_,"pds_nack",packet.PDS_header.nack_header.nack_code);
                wake();
            } catch (const std::invalid_argument&) { trace_.record(node_, "malformed_frame"); }
        });
    }
    ~PdsHost() { close(); }
    PdsHost(const PdsHost&) = delete;
    PdsHost& operator=(const PdsHost&) = delete;

    PDSProcessManager& manager() { return manager_; }
    // Configure before submitting work. The owning runtime remains responsible
    // for progress; changing resource policy does not create background work.
    Services& services() { return services_; }
    void configure_retransmission_timeout(Time timeout_ns) {
        if (stopped_ || manager_.getPDSStatus().open_cnt) throw std::logic_error("configure RTO before opening connections");
        if (timeout_ns>kMaximumInitialRtoNs) throw std::invalid_argument("initial RTO exceeds UE 1.1 eight-second range");
        services_.rto_ns=timeout_ns;
    }
    void enable_nscc(const CMS::NsccConfig& config) {
        if (stopped_ || format_!=WireFormat::Uet11 || services_.congestion_control || manager_.getPDSStatus().open_cnt)
            throw std::logic_error("configure NSCC once before opening connections");
        congestion_=std::make_unique<CMS::NsccEngine>(config,loop_,[this] { wake(); },network_,&trace_,node_);
        services_.congestion_control=congestion_.get();
    }
    const CMS::NsccEngine* nscc() const { return congestion_.get(); }
    void configure_trimming(const NetworkLayer::TrimmingOptions& options) {
        options.validate();
        if (stopped_ || format_!=WireFormat::Uet11 || manager_.getPDSStatus().open_cnt)
            throw std::logic_error("configure trimming before opening connections");
        trimming_=options;
    }
    void cancel_queued_message(uint32_t peer,uint32_t job,uint16_t message_id) {
        if (!stopped_) manager_.cancelQueuedMessage(peer,job,message_id);
    }
    bool request_connection_close(uint16_t local_pdc_id) {
        if (stopped_ || !manager_.requestConnectionClose(local_pdc_id)) return false;
        wake();
        return true;
    }
    bool request_connection_probe(uint16_t local_pdc_id,uint32_t selective_base) {
        if (stopped_ || !manager_.requestConnectionProbe(local_pdc_id,selective_base)) return false;
        wake(); return true;
    }
    void set_request_handler(std::function<void(const PDC_SES_req&)> callback) { request_handler_ = std::move(callback); }
    // Establish the transport without inventing an SES NO_OP message. The
    // optional negotiation request uses NO_NEG and enables no optional feature.
    uint16_t open_connection(uint32_t peer,uint32_t job=1,pdc_mode mode=ROD,bool negotiation=false) {
        if (stopped_ || format_!=WireFormat::Uet11) return UINT16_MAX;
        const auto context=manager_.openWithControl(node_,peer,job,mode,negotiation);
        if (context!=UINT16_MAX) wake();
        return context;
    }
    void set_response_handler(std::function<void(const PDC_SES_rsp&)> callback) { response_handler_ = std::move(callback); }
    void set_datagram_transmit_handler(std::function<void(uint16_t,SendResult)> callback) {
        datagram_transmit_handler_ = std::move(callback);
    }
    void set_context_event_handler(std::function<void(const PdcEvent&)> callback) {
        context_event_handler_=std::move(callback);
    }
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
        context_events_.clear();
        transmit_notifications_.clear();
        trace_.record(node_, "host_closed");
    }
private:
    uint32_t node_;
    EventLoop& loop_;
    Trace& trace_;
    IPacketPort& port_;
    Services services_;
    std::unique_ptr<CMS::NsccEngine> congestion_; // Outlives every PDC in manager_.
    PDSProcessManager manager_;
    std::shared_ptr<int> lifetime_ = std::make_shared<int>(0);
    TimerId pending_ = 0;
    bool stopped_ = false;
    struct OutboundFrame {
        Frame frame;
        bool is_datagram;
        uint16_t local_tx_handle;
        std::optional<TransmitIdentity> identity;
    };
    std::deque<OutboundFrame> outbound_;
    std::deque<TransmitNotification> transmit_notifications_;
    std::function<void(uint16_t,SendResult)> datagram_transmit_handler_;
    std::deque<PdcEvent> context_events_;
    std::function<void(const PdcEvent&)> context_event_handler_;
    std::function<void(const PDC_SES_req&)> request_handler_;
    std::function<void(const PDC_SES_rsp&)> response_handler_;
    WireFormat format_;
    NetworkLayer::WireOptions network_;
    std::optional<NetworkLayer::TrimmingOptions> trimming_;

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
            bool worked=false;
            while (!transmit_notifications_.empty()) {
                const auto notification=transmit_notifications_.front(); transmit_notifications_.pop_front();
                if (manager_.notifyTransmit(notification))
                    trace_.record(node_,notification.outcome==TransmitOutcome::Started?"mac_tx":"nic_rejected",notification.identity.sequence);
                worked=true;
            }
            worked=manager_.progressOne() || worked;
            // Retire old semantic state before delivering requests that may
            // reuse an identifier cleared by the same PDS progress step.
            while (!context_events_.empty()) {
                const auto event=context_events_.front(); context_events_.pop_front();
                if (context_event_handler_) context_event_handler_(event);
                if (stopped_) return;
                worked=true;
            }
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
                    const bool data=packet.PDS_type==RUOD_req_header || packet.PDS_type==UUD_req_header;
                    if (services_.congestion_control || !data) options.entropy=packet.wire_entropy;
                    frame.entropy=options.entropy; // ECMP uses the actual on-wire EV, including without CMS.
                    if (services_.congestion_control) {
                        options.ecn=packet.network_ecn;
                        if (packet.PDS_type==UUD_req_header) options.ecn=2; // ECT without reliable NSCC admission.
                    }
                    if (trimming_ && data) options.dscp=trimming_->trimmable_dscp;
                    if ((services_.congestion_control || trimming_) && !data) {
                        frame.traffic_class=1;
                        options.dscp=trimming_?trimming_->control_dscp:48;
                    }
                    frame.bytes=NetworkLayer::UetWireCodec::encode(packet,options);
                    if (services_.congestion_control && packet.PDS_type==RUOD_ack_header &&
                        packet.PDS_header.RUOD_ack_header.type==ACK_CC && packet.acknowledgment_trigger_arrival_ns) {
                        const auto arrival=*packet.acknowledgment_trigger_arrival_ns;
                        frame.prepare_transmission=[arrival,crc=options.crc,protocol=options.native_ip_protocol](uint64_t departure,std::vector<uint8_t>& bytes) {
                            NetworkLayer::UetWireCodec::stamp_service_time(bytes,departure,arrival,crc,protocol);
                        };
                    }
                }
                if (packet.transmit_identity) {
                    const auto identity=*packet.transmit_identity;
                    std::weak_ptr<int> lifetime=lifetime_;
                    frame.transmission_event=[this,lifetime,identity](uint64_t time,TransmitOutcome outcome) {
                        if (lifetime.expired() || stopped_) return;
                        transmit_notifications_.push_back({identity,time,outcome});
                        wake(); // The NIC never re-enters a PDC state machine.
                    };
                }
                outbound_.push_back({std::move(frame),packet.PDS_type==UUD_req_header,packet.local_tx_handle,packet.transmit_identity});
                trace_.record(node_, "pds_tx", static_cast<uint64_t>(packet.PDS_type));
                if (packet.PDS_type==RUOD_cp_header)
                    trace_.record(node_,"pds_control",packet.PDS_header.RUOD_cp_header.ctl_type);
                worked = true;
            }
            while (!outbound_.empty()) {
                auto& queued=outbound_.front();
                std::optional<Frame> submission_frame;
                if (!services_.actual_transmit_notifications && queued.frame.prepare_transmission) {
                    // Unsupported adapters expose the send-submission boundary.
                    // Keep the original hook if WouldBlock requires a later try.
                    submission_frame=queued.frame; prepare_first_transmission(*submission_frame,loop_.now());
                }
                const auto result=port_.try_send(submission_frame?*submission_frame:queued.frame);
                if (result == SendResult::WouldBlock) {
                    // No busy polling: external adapters call wake() when writable.
                    return;
                }
                if (result != SendResult::Accepted) {
                    trace_.record(node_, "port_drop", static_cast<uint64_t>(result));
                    if (queued.identity) {
                        transmit_notifications_.push_back({*queued.identity,loop_.now(),TransmitOutcome::Rejected});
                        wake();
                    }
                }
                const auto transmitted=std::move(outbound_.front());
                outbound_.pop_front();
                if (transmitted.is_datagram && datagram_transmit_handler_)
                    datagram_transmit_handler_(transmitted.local_tx_handle,result);
                if (stopped_) return;
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
                    trace_.record(node_, "ses_response",response.original_sequence);
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
