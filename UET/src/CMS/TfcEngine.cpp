#include "TfcEngine.hpp"
#include "NsccEngine.hpp"

namespace UET::CMS {

// Source and destination credit transitions compile once for all consumers.
// TfcEngine.hpp retains the CMS interface and per-CCC ownership state.

TfcEngine::TfcEngine(TfcEngineConfig config,Runtime::IClock& clock,Runtime::ITimerQueue& timers,
              std::function<void()> wake,NetworkLayer::WireOptions wire,NsccEngine* nscc,
              Runtime::Trace* trace,uint32_t node)
        : config_(config),clock_(clock),timers_(timers),wake_(std::move(wake)),wire_(wire),
          nscc_(nscc),trace_(trace),node_(node) { config_.validate(); }

TfcEngine::~TfcEngine() {
    lifetime_.reset();
    for (const auto& binding:sources_) cancel_timer(*binding.second);
}

auto TfcEngine::config() const -> const TfcEngineConfig& { return config_; }

auto TfcEngine::accepts_credit_requests() const -> bool { return true; }

auto TfcEngine::opened(const Connection& connection) -> void {
    if (nscc_) nscc_->opened(connection);
}

auto TfcEngine::work_posted(const Connection& connection,uint64_t payload_bytes) -> void {
    const auto cost=TfcSourceCredit(config_.outgoing).packet_credit_bytes(payload_bytes);
    auto& posted=posted_bytes_[connection];
    if (cost>UINT64_MAX-posted) throw std::overflow_error("TFC posted work exhausted byte accounting");
    posted+=cost;
    if (const auto found=sources_.find(connection);found!=sources_.end()) add_posted_work(connection,*found->second);
}

auto TfcEngine::can_send(const Connection& connection) -> bool { return can_send_attempt(connection,false); }

auto TfcEngine::can_send_attempt(const Connection& connection,bool retransmission) -> bool {
    auto context=source_context(connection);
    const bool allowed=context && context->credit.can_send(retransmission) &&
        (!nscc_ || nscc_->can_send(connection));
    if (!allowed) record("tfc_blocked",connection.local_pdc);
    return allowed;
}

auto TfcEngine::transmitted(const Connection& connection,PDStoNET_pkt& packet) -> uint32_t {
    return transmitted_attempt(connection,packet,false);
}

auto TfcEngine::transmitted_attempt(const Connection& connection,PDStoNET_pkt& packet,bool retransmission) -> uint32_t {
    auto context=source_context(connection);
    if (!context) throw std::logic_error("TFC packet transmitted without an allocated source CCC");
    context->credit.on_send(packet.SESpkt.payload.size(),retransmission);
    auto& request=packet.PDS_header.RUOD_req_header;
    request.type=connection.ordered ? ROD_CC_REQ : RUD_CC_REQ;
    packet.credit_request.ccc_id=context->identifier;
    packet.credit_request.credit_target_units=static_cast<uint32_t>((context->posted_bytes>>8)&0xffffff);
    if (nscc_) return nscc_->transmitted(connection,packet);
    packet.wire_entropy=connection.ordered ? path(connection) : next_entropy_++;
    packet.network_ecn=2;
    record(retransmission ? "tfc_retransmitted" : "tfc_new_packet",packet.SESpkt.payload.size());
    return static_cast<uint32_t>(NetworkLayer::UetWireCodec::encode(packet,wire_).size()-
        14-(wire_.ipv6 ? 40 : 20)+40);
}

auto TfcEngine::decorate_control(const Connection& connection,PDStoNET_pkt& packet) -> void {
    if (nscc_) nscc_->decorate_control(connection,packet);
    else packet.wire_entropy=connection.ordered ? path(connection) : next_entropy_++;
}

auto TfcEngine::admit_receive(const Connection& connection,const PDStoNET_pkt& packet) -> std::optional<PDS_Nack_Codes> {
    const auto& header=packet.PDS_header.RUOD_req_header;
    if (header.type!=RUD_CC_REQ && header.type!=ROD_CC_REQ) return UET_PDC_HDR_MISMATCH;
    try { TfcSourceCredit(config_.incoming).packet_credit_bytes(packet.SESpkt.payload.size()); }
    catch (const std::invalid_argument&) { return UET_NO_PKT_BUFFER; }
    auto binding=receivers_.find(connection);
    if (binding!=receivers_.end() && binding->second.context->identifier!=packet.credit_request.ccc_id)
        return UET_PDC_HDR_MISMATCH;
    if (binding==receivers_.end()) {
        const DestinationKey key{connection.peer,packet.credit_request.ccc_id};
        auto found=destinations_.find(key);
        if (found==destinations_.end()) {
            if (config_.receive_context_bytes>config_.receive_pool_bytes-reserved_receive_bytes_)
                return UET_NO_CCC_AVAIL;
            auto context=std::make_shared<DestinationContext>(config_,packet.credit_request.ccc_id);
            found=destinations_.emplace(key,std::move(context)).first;
            reserved_receive_bytes_+=config_.receive_context_bytes;
            record("tfc_reserved_bytes",reserved_receive_bytes_);
        }
        binding=receivers_.emplace(connection,Receiver{found->second,{}}).first;
        found->second->members.insert(connection);
    }
    try {
        if (!binding->second.context->budget.can_accept_new_packet(packet.SESpkt.payload.size()))
            return UET_NO_PKT_BUFFER;
    } catch (const std::invalid_argument&) { return UET_NO_PKT_BUFFER; }
    // No buffer is consumed here: SES may still refuse its own independent
    // bookkeeping reservation. received() commits after PDS admission.
    return {};
}

auto TfcEngine::received(const Connection& connection,const PDStoNET_pkt& packet,bool duplicate) -> void {
    if (nscc_) nscc_->received(connection,packet,duplicate);
    const auto found=receivers_.find(connection);
    if (found==receivers_.end() || found->second.context->identifier!=packet.credit_request.ccc_id) return;
    auto& receiver=found->second;
    if (!duplicate) receiver.leases.emplace(packet.PDS_header.RUOD_req_header.psn,
        receiver.context->budget.accept_new_packet(packet.SESpkt.payload.size()));
    receiver.context->budget.observe_credit_target(packet.credit_request.credit_target_units);
    grant_available(*receiver.context);
}

auto TfcEngine::handed_to_semantics(const Connection& connection,uint32_t psn) -> void {
    const auto found=receivers_.find(connection);
    if (found==receivers_.end()) return;
    auto& receiver=found->second;
    const auto lease=receiver.leases.find(psn);
    if (lease==receiver.leases.end()) return;
    receiver.context->budget.release_packet(lease->second);
    receiver.leases.erase(lease);
    grant_available(*receiver.context);
}

auto TfcEngine::decorate_ack(const Connection& connection,uint32_t psn,PDStoNET_pkt& packet) -> void {
    if (nscc_) { nscc_->decorate_ack(connection,psn,packet); return; }
    const auto found=receivers_.find(connection);
    if (found==receivers_.end()) return;
    packet.PDS_header.RUOD_ack_header.type=ACK_CC;
    packet.congestion_ack.type=1;
    packet.congestion_ack.credit_units=found->second.context->budget.cumulative_credit_units();
    packet.congestion_ack.out_of_order_count=0xffff; // TFC ignores this estimate (§3.6.15).
    found->second.context->credit_due=false;
}

auto TfcEngine::acknowledged(const Connection& connection,const PDStoNET_pkt& packet,
                      std::optional<NsccTransmitSample> sample) -> void {
    if (packet.PDS_header.RUOD_ack_header.type==ACK_CC && packet.congestion_ack.type==1)
        apply_credit(connection,packet.congestion_ack.credit_units);
    if (nscc_) nscc_->acknowledged(connection,packet,sample);
}

auto TfcEngine::negative_acknowledged(const Connection& connection,uint32_t bytes,const PDStoNET_pkt& packet,
                               std::optional<NsccTransmitSample> sample) -> void {
    if (nscc_) nscc_->negative_acknowledged(connection,bytes,packet,sample);
}

auto TfcEngine::negative_acknowledgment_event(const Connection& connection,const PDStoNET_pkt& packet) -> void {
    if (nscc_) nscc_->negative_acknowledgment_event(connection,packet);
}

auto TfcEngine::inferred_loss(const Connection& connection,uint32_t bytes) -> void {
    if (nscc_) nscc_->inferred_loss(connection,bytes);
}

auto TfcEngine::canceled_unsent_retry(const Connection& connection,uint32_t bytes) -> void {
    if (nscc_) nscc_->canceled_unsent_retry(connection,bytes);
}

auto TfcEngine::receive_cleared(const Connection& connection,uint32_t through) -> void {
    if (nscc_) nscc_->receive_cleared(connection,through);
}

auto TfcEngine::update_activity(const Connection& connection,bool established,bool unsent,bool unacknowledged,
                         bool quiescing,uint64_t rto_ns) -> void {
    activity_[connection]={established,unsent,unacknowledged,quiescing,rto_ns};
    const auto found=sources_.find(connection);
    if (found==sources_.end()) return;
    auto& context=*found->second;
    const bool all_quiescing=std::all_of(context.members.begin(),context.members.end(),[&](const auto& member) {
        const auto activity=activity_.find(member);
        return activity!=activity_.end() && activity->second.quiescing;
    });
    // §3.6.15.3: keep the old CCC alive for its closing PDCs, but remove
    // it from lookup before any new PDC can bind to its old reservation.
    if (all_quiescing && !context.retired) {
        context.retired=true;
        const auto shared=shared_sources_.find(context.key);
        if (shared!=shared_sources_.end() && shared->second.get()==&context) shared_sources_.erase(shared);
        cancel_timer(context);
        context.request_due=false;
    }
    refresh_timer(context);
}

auto TfcEngine::has_credit_control(const Connection& connection) const -> bool {
    const auto activity=activity_.find(connection);
    if (activity==activity_.end() || !activity->second.established) return false;
    const auto receiver=receivers_.find(connection);
    if (receiver!=receivers_.end() && receiver->second.context->credit_due) return true;
    const auto source=sources_.find(connection);
    return source!=sources_.end() && source->second->request_due && !activity->second.quiescing;
}

auto TfcEngine::take_credit_control(const Connection& connection) -> std::optional<CreditControlMessage> {
    if (!has_credit_control(connection)) return {};
    const auto receiver=receivers_.find(connection);
    if (receiver!=receivers_.end() && receiver->second.context->credit_due) {
        auto& context=*receiver->second.context;
        context.credit_due=false;
        return CreditControlMessage{Credit,context.budget.cumulative_credit_units()<<8};
    }
    auto& context=*sources_.at(connection);
    context.request_due=false;
    refresh_timer(context);
    return CreditControlMessage{Credit_req,(uint32_t{context.identifier}<<24)|
        static_cast<uint32_t>((context.posted_bytes>>8)&0xffffff)};
}

auto TfcEngine::received_credit_control(const Connection& connection,const PDStoNET_pkt& packet) -> void {
    const auto& control=packet.PDS_header.RUOD_cp_header;
    if (control.psn || control.flags.ar || control.flags.syn) return;
    if (control.ctl_type==Credit) apply_credit(connection,control.payload>>8);
    else if (control.ctl_type==Credit_req) {
        const auto receiver=receivers_.find(connection);
        if (receiver==receivers_.end() || receiver->second.context->identifier!=(control.payload>>24)) return;
        auto& context=*receiver->second.context;
        context.budget.observe_credit_target(control.payload&0xffffff);
        grant_available(context);
        context.credit_due=true; // Repeat cumulative feedback even if the previous grant CP was lost.
        if (wake_) wake_();
    }
}

auto TfcEngine::closed(const Connection& connection) -> void {
    const auto source=sources_.find(connection);
    if (source!=sources_.end()) {
        auto context=source->second;
        context->members.erase(connection);
        context->accounted_posted.erase(connection);
        sources_.erase(source);
        if (context->members.empty()) {
            cancel_timer(*context);
            const auto shared=shared_sources_.find(context->key);
            if (shared!=shared_sources_.end() && shared->second==context) shared_sources_.erase(shared);
            identifiers_[connection.peer].erase(context->identifier);
        } else refresh_timer(*context);
    }
    const auto receiver=receivers_.find(connection);
    if (receiver!=receivers_.end()) {
        auto context=receiver->second.context;
        for (const auto& lease:receiver->second.leases) context->budget.release_packet(lease.second);
        context->members.erase(connection);
        receivers_.erase(receiver);
        if (context->members.empty()) {
            destinations_.erase({connection.peer,context->identifier});
            reserved_receive_bytes_-=config_.receive_context_bytes;
            record("tfc_reserved_bytes",reserved_receive_bytes_);
        } else grant_available(*context);
    }
    posted_bytes_.erase(connection);
    activity_.erase(connection);
    paths_.erase(connection);
    if (nscc_) nscc_->closed(connection);
    if (wake_) wake_();
}

auto TfcEngine::reserved_receive_bytes() const -> uint64_t { return reserved_receive_bytes_; }

auto TfcEngine::destination_context_count() const -> size_t { return destinations_.size(); }

auto TfcEngine::source_connection_count() const -> size_t { return sources_.size(); }

auto TfcEngine::source_credit_bytes(const Connection& connection) const -> int64_t { return sources_.at(connection)->credit.available_credit_bytes(); }

auto TfcEngine::source_identifier(const Connection& connection) const -> uint8_t { return sources_.at(connection)->identifier; }

auto TfcEngine::path(const Connection& connection) -> uint16_t {
    const auto found=paths_.find(connection);
    if (found!=paths_.end()) return found->second;
    return paths_.emplace(connection,next_entropy_++).first->second;
}

auto TfcEngine::source_context(const Connection& connection) -> std::shared_ptr<SourceContext> {
    if (const auto found=sources_.find(connection);found!=sources_.end()) return found->second;
    const bool private_context=connection.ordered || !config_.share_unordered_contexts;
    // Keep delivery mode in the group identity even when RUD sharing is
    // disabled; private RUD and ROD contexts are separate kinds of CCC.
    const SourceKey key{connection.peer,connection.ordered,private_context ? connection.local_pdc : uint16_t{0},
        private_context ? connection.starting_psn : 0};
    auto shared=shared_sources_.find(key);
    if (shared==shared_sources_.end()) {
        auto& used=identifiers_[connection.peer];
        unsigned identifier=0;
        while (identifier<256 && used.count(static_cast<uint8_t>(identifier))) ++identifier;
        if (identifier==256) return {}; // Existing PDCs can release a CCC and wake this blocked producer.
        auto context=std::make_shared<SourceContext>(config_.outgoing,key,static_cast<uint8_t>(identifier));
        shared=shared_sources_.emplace(key,std::move(context)).first;
        used.insert(static_cast<uint8_t>(identifier));
    }
    auto context=shared->second;
    context->members.insert(connection);
    sources_.emplace(connection,context);
    add_posted_work(connection,*context);
    return context;
}

auto TfcEngine::add_posted_work(const Connection& connection,SourceContext& context) -> void {
    auto& previous=context.accounted_posted[connection];
    const auto total=posted_bytes_[connection];
    const auto additional=total-previous;
    if (additional>UINT64_MAX-context.posted_bytes) throw std::overflow_error("TFC shared CCC demand exhausted");
    context.posted_bytes+=additional;
    previous=total;
}

auto TfcEngine::grant_available(DestinationContext& context) -> void {
    if (context.budget.allocate_credit()) {
        context.credit_due=true;
        record("tfc_granted_bytes",context.budget.granted_bytes());
        if (wake_) wake_();
    }
}

auto TfcEngine::apply_credit(const Connection& connection,uint32_t units) -> void {
    const auto found=sources_.find(connection);
    if (found==sources_.end()) return;
    if (found->second->credit.on_credit_update(units)) {
        record("tfc_credit_received",units);
        found->second->request_due=false;
        refresh_timer(*found->second);
        if (wake_) wake_();
    }
}

auto TfcEngine::cancel_timer(SourceContext& context) -> void {
    if (context.timer) timers_.cancel(context.timer);
    context.timer=0;
}

auto TfcEngine::refresh_timer(SourceContext& context) -> void {
    bool unsent=false,pending=false,established=false;
    uint64_t rto=UINT64_MAX;
    for (const auto& member:context.members) {
        const auto found=activity_.find(member);
        if (found==activity_.end()) continue;
        unsent|=found->second.unsent;
        pending|=found->second.unacknowledged;
        established|=found->second.established && !found->second.quiescing;
        rto=std::min(rto,found->second.rto_ns);
    }
    if (context.retired || !unsent || pending || !established || context.credit.can_send()) {
        cancel_timer(context);
        context.request_due=false;
        return;
    }
    if (context.timer || context.request_due) return;
    // §3.6.15.4 prose starts recovery when new work is credit-blocked
    // with no pending data RTO. Its READY guard conflicts with §3.6.8's
    // ACTIVE/READY definitions; this explicit simulator interpretation
    // follows that recovery condition (recorded in the conformance notes).
    const std::weak_ptr<int> life=lifetime_;
    const auto source=sources_.find(*context.members.begin())->second;
    const std::weak_ptr<SourceContext> weak_context=source;
    context.timer=timers_.at(Runtime::add_time(clock_.now(),std::max<uint64_t>(1,rto)),[this,life,weak_context] {
        if (life.expired()) return;
        const auto context=weak_context.lock();
        if (!context) return;
        context->timer=0;
        context->request_due=true;
        record("tfc_credit_timer",context->identifier);
        if (wake_) wake_();
    });
}

auto TfcEngine::record(const char* event,uint64_t value) -> void { if (trace_) trace_->record(node_,event,value); }

} // namespace UET::CMS
