#pragma once
#include "Runtime.hpp"
#include "PacketPort.hpp"
#include "../Network_Layer/PdsPacketCodec.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include "../PDS/DefaultSemanticResponse.hpp"
#include "../CMS/NsccEngine.hpp"
#include "../CMS/TfcEngine.hpp"
#include "../SES/SemanticReturnCode.hpp"
#include "../PDS/PDS_Manager/process/PDSProcessManager.hpp"
#include <deque>

namespace UET::Runtime {

// Runs the existing Soft-UE PDS_Manager/IPDC/TPDC, rather than a second PDS.
// The legacy wire codec is explicit until the standard codec is selected.
// PdsHost.cpp owns progress and wire adaptation; this header exposes the
// per-Host interface and the state needed by the original PDS bridge.
class PdsHost {
public:
    enum class WireFormat { Uet11, LegacySup1 };
    PdsHost(uint32_t node, EventLoop& loop, Trace& trace, IPacketPort& port,
            WireFormat format = WireFormat::Uet11,
            NetworkLayer::WireOptions network = {});
    ~PdsHost();
    PdsHost(const PdsHost&) = delete;
    PdsHost& operator=(const PdsHost&) = delete;

    PDSProcessManager& manager();
    bool closed() const;
    static RetiredSemanticReceives::Key semantic_receive_identity(const PDC_SES_req& request);
    // Configure before submitting work. The owning runtime remains responsible
    // for progress; changing resource policy does not create background work.
    Services& services();
    const PDS::ReceiveErrorCounters& pds_error_counters() const;
    void clear_pds_error_counters();
    void configure_retransmission_timeout(Time timeout_ns);
    void configure_negative_acknowledgment_delays(const std::array<Time,4>& delays_ns);
    void configure_retry_limit(uint32_t maximum_retries);
    void configure_initial_sequence_seed(uint64_t scenario_seed);
    void enable_nscc(const CMS::NsccConfig& config);
    const CMS::NsccEngine* nscc() const;
    // Experimental transport-credit policy. Configure optional NSCC first;
    // this adapter currently uses the host's one data traffic class (TC 0).
    void enable_tfc(const CMS::TfcEngineConfig& config);
    const CMS::TfcEngine* tfc() const;
    void configure_psn_ranges(const PDS::PsnRangeConfiguration& configured,uint32_t zero_override=0);
    void configure_pdc_mapping(const PDS::PdcMappingConfiguration& configured);
    void configure_read_ack_data(uint32_t maximum_bytes);
    void configure_semantic_payload_mtu(uint32_t payload_bytes);
    void configure_trimming(const NetworkLayer::TrimmingOptions& options);
    void cancel_queued_message(uint32_t peer,uint32_t job,uint16_t message_id);
    bool request_connection_close(uint16_t local_pdc_id);
    bool request_connection_probe(uint16_t local_pdc_id,uint32_t selective_base);
    void set_request_handler(std::function<void(const PDC_SES_req&)> callback);
    void set_receive_admission(std::function<SemanticAdmission(const PDC_SES_req&)> reserve,
                               std::function<void(const PDC_SES_req&)> cancel);
    // Establish the transport without inventing an SES NO_OP message. The
    // optional negotiation request uses NO_NEG and enables no optional feature.
    uint16_t open_connection(uint32_t peer,uint32_t job=1,pdc_mode mode=ROD,bool negotiation=false,
                             PDS::PdcMappingIdentity identity={});
    void set_response_handler(std::function<void(const PDC_SES_rsp&)> callback);
    void set_datagram_transmit_handler(std::function<void(uint16_t,SendResult)> callback);
    void set_context_event_handler(std::function<void(const PdcEvent&)> callback);
    bool submit(const SES_PDS_req& request);
    std::optional<uint32_t> submit_rudi(const SES_PDS_req& request);
    bool respond_rudi(const PDC_SES_req& request,const SEStoPDS_pkt& response);
    bool submit_return_data(const PDC_SES_req& original,const SEStoPDS_pkt& data);
    void wake();
    void close();
private:
    void answer_inactive_receive(const PDC_SES_req& request);
    bool answer_retired_receive(const PDC_SES_req& request);
    static uint64_t sequence_seed_for_host(uint64_t scenario_seed,uint32_t host);
    uint32_t node_;
    EventLoop& loop_;
    Trace& trace_;
    IPacketPort& port_;
    Services services_;
    std::unique_ptr<CMS::NsccEngine> congestion_; // Outlives every PDC in manager_.
    std::unique_ptr<CMS::TfcEngine> flow_control_; // Destroyed before optional underlying NSCC.
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

    NetworkLayer::WireAddress address(uint32_t node) const;

    void pump();
};
} // namespace UET::Runtime
