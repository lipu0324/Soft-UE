#pragma once
#include "CongestionControl.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include "TfcDestinationCredit.hpp"
#include "../Runtime/Runtime.hpp"
#include <set>

namespace UET::CMS {

class NsccEngine;

struct TfcEngineConfig {
    // Outgoing geometry describes the peer's transport buffers. Incoming
    // geometry describes this host's buffers; asymmetric links are permitted.
    TfcSourceConfig outgoing;
    TfcSourceConfig incoming;
    uint64_t receive_context_bytes=131072;
    uint64_t receive_pool_bytes=16777216;
    bool share_unordered_contexts=true;

    void validate() const {
        outgoing.validate();
        incoming.validate();
        TfcDestinationCredit check(incoming,receive_context_bytes);
        if (receive_pool_bytes<receive_context_bytes)
            throw std::invalid_argument("TFC host pool must cover at least one destination CCC");
    }
};

// TFC composes with the original optional NSCC engine. PDS still owns PSNs,
// loss recovery, duplicate suppression and connection identity. The engine
// owns source CCCs and separately reserved destination CCC buffer budgets.
// Every callback runs on the injected single-owner runtime.
class TfcEngine final : public ICongestionControl {
public:
    TfcEngine(TfcEngineConfig config,Runtime::IClock& clock,Runtime::ITimerQueue& timers,
              std::function<void()> wake,NetworkLayer::WireOptions wire,NsccEngine* nscc=nullptr,
              Runtime::Trace* trace=nullptr,uint32_t node=0);
    ~TfcEngine() override;
    const TfcEngineConfig& config() const;
    bool accepts_credit_requests() const override;
    void opened(const Connection& connection) override;
    void work_posted(const Connection& connection,uint64_t payload_bytes) override;
    bool can_send(const Connection& connection) override;
    bool can_send_attempt(const Connection& connection,bool retransmission) override;
    uint32_t transmitted(const Connection& connection,PDStoNET_pkt& packet) override;
    uint32_t transmitted_attempt(const Connection& connection,PDStoNET_pkt& packet,bool retransmission) override;
    void decorate_control(const Connection& connection,PDStoNET_pkt& packet) override;

    std::optional<PDS_Nack_Codes> admit_receive(const Connection& connection,const PDStoNET_pkt& packet) override;
    void received(const Connection& connection,const PDStoNET_pkt& packet,bool duplicate=false) override;
    void handed_to_semantics(const Connection& connection,uint32_t psn) override;
    void decorate_ack(const Connection& connection,uint32_t psn,PDStoNET_pkt& packet) override;
    void acknowledged(const Connection& connection,const PDStoNET_pkt& packet,
                      std::optional<NsccTransmitSample> sample) override;
    void negative_acknowledged(const Connection& connection,uint32_t bytes,const PDStoNET_pkt& packet,
                               std::optional<NsccTransmitSample> sample) override;
    void negative_acknowledgment_event(const Connection& connection,const PDStoNET_pkt& packet) override;
    void inferred_loss(const Connection& connection,uint32_t bytes) override;
    void canceled_unsent_retry(const Connection& connection,uint32_t bytes) override;
    void receive_cleared(const Connection& connection,uint32_t through) override;

    void update_activity(const Connection& connection,bool established,bool unsent,bool unacknowledged,
                         bool quiescing,uint64_t rto_ns) override;
    bool has_credit_control(const Connection& connection) const override;
    std::optional<CreditControlMessage> take_credit_control(const Connection& connection) override;
    void received_credit_control(const Connection& connection,const PDStoNET_pkt& packet) override;
    void closed(const Connection& connection) override;

    uint64_t reserved_receive_bytes() const;
    size_t destination_context_count() const;
    size_t source_connection_count() const;
    int64_t source_credit_bytes(const Connection& connection) const;
    uint8_t source_identifier(const Connection& connection) const;

private:
    using SourceKey=std::tuple<uint32_t,bool,uint16_t,uint32_t>;
    using DestinationKey=std::pair<uint32_t,uint8_t>;
    struct SourceContext {
        SourceContext(const TfcSourceConfig& geometry,SourceKey group,uint8_t id)
            : credit(geometry),key(group),identifier(id) {}
        TfcSourceCredit credit;
        SourceKey key;
        uint8_t identifier;
        uint64_t posted_bytes=0;
        std::map<Connection,uint64_t> accounted_posted;
        std::set<Connection> members;
        Runtime::TimerId timer=0;
        bool request_due=false,retired=false;
    };
    struct DestinationContext {
        DestinationContext(const TfcEngineConfig& config,uint8_t id)
            : budget(config.incoming,config.receive_context_bytes),identifier(id) {}
        TfcDestinationCredit budget;
        uint8_t identifier;
        std::set<Connection> members;
        bool credit_due=false;
    };
    struct Receiver {
        std::shared_ptr<DestinationContext> context;
        std::map<uint32_t,TfcDestinationCredit::BufferLease> leases;
    };
    struct Activity { bool established,unsent,unacknowledged,quiescing; uint64_t rto_ns; };
    const TfcEngineConfig config_;
    Runtime::IClock& clock_;
    Runtime::ITimerQueue& timers_;
    std::function<void()> wake_;
    NetworkLayer::WireOptions wire_;
    NsccEngine* nscc_;
    Runtime::Trace* trace_;
    uint32_t node_;
    std::shared_ptr<int> lifetime_=std::make_shared<int>(0);
    std::map<SourceKey,std::shared_ptr<SourceContext>> shared_sources_;
    std::map<Connection,std::shared_ptr<SourceContext>> sources_;
    std::map<DestinationKey,std::shared_ptr<DestinationContext>> destinations_;
    std::map<Connection,Receiver> receivers_;
    std::map<uint32_t,std::set<uint8_t>> identifiers_;
    std::map<Connection,uint64_t> posted_bytes_;
    std::map<Connection,Activity> activity_;
    std::map<Connection,uint16_t> paths_;
    uint64_t reserved_receive_bytes_=0;
    uint16_t next_entropy_=1;

    uint16_t path(const Connection& connection);
    std::shared_ptr<SourceContext> source_context(const Connection& connection);
    void add_posted_work(const Connection& connection,SourceContext& context);
    void grant_available(DestinationContext& context);
    void apply_credit(const Connection& connection,uint32_t units);
    void cancel_timer(SourceContext& context);
    void refresh_timer(SourceContext& context);
    void record(const char* event,uint64_t value);
};

} // namespace UET::CMS
