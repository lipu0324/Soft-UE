#pragma once
#include "CongestionControl.hpp"
#include "../Runtime/Runtime.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <map>
#include <memory>

namespace UET::CMS {
// Binds the congestion law to a host, preserving per-PDC counters while sharing
// a congestion control context (CCC) across sprayed RUD PDCs to a destination.
// Ordered ROD PDCs have independent CCCs and retain one entropy/path value.
class NsccEngine final : public ICongestionControl {
public:
    NsccEngine(NsccConfig config,Runtime::IClock& clock,std::function<void()> wake,
               NetworkLayer::WireOptions wire,Runtime::Trace* trace=nullptr,uint32_t node=0)
        :config_(config),clock_(clock),wake_(std::move(wake)),wire_(wire),trace_(trace),node_(node) { config_.validate(); }
    bool can_send(const Connection& connection) override {
        const bool ready=source(connection).controller->can_send();
        if (!ready) record("nscc_blocked",connection.local_pdc);
        return ready;
    }
    uint32_t transmitted(const Connection& connection,PDStoNET_pkt& packet) override {
        auto& state=source(connection);
        packet.wire_entropy=connection.ordered?state.fixed_entropy:next_entropy_++;
        packet.network_ecn=2; // ECT(0), §3.6.4.1.
        const auto bytes=NetworkLayer::UetWireCodec::encode(packet,wire_).size()-14-(wire_.ipv6?40:20)+40;
        if (bytes>config_.nominal_mtu) throw std::invalid_argument("packet exceeds configured NSCC nominal MTU");
        state.controller->on_send(static_cast<uint32_t>(bytes),clock_.now());
        state.inflight_contribution+=static_cast<int64_t>(bytes);
        if (state.controller->request_ack(1)) packet.PDS_header.RUOD_req_header.flags.ar=1;
        record("nscc_inflight",state.controller->state().inflight_bytes>0?state.controller->state().inflight_bytes:0);
        record("nscc_window",state.controller->state().congestion_window);
        return static_cast<uint32_t>(bytes);
    }
    void decorate_control(const Connection& connection,PDStoNET_pkt& packet) override {
        auto& state=source(connection);
        // ROD's forward requests and controls retain their CCC's one path.
        // RUD may spray controls too. Control traffic does not consume cwnd.
        packet.wire_entropy=connection.ordered?state.fixed_entropy:next_entropy_++;
    }
    void acknowledged(const Connection& connection,const PDStoNET_pkt& packet,
                       std::optional<NsccTransmitSample> sample) override {
        if (packet.PDS_header.RUOD_ack_header.type!=ACK_CC || packet.congestion_ack.type!=0) return;
        const auto found=sources_.find(connection);
        if (found==sources_.end()) return; // No request ever sent in this direction.
        auto& state=found->second;
        const auto& feedback=packet.congestion_ack;
        NsccAck ack;
        ack.newly_received_bytes=state.byte_counter.acknowledge(feedback.received_byte_units);
        ack.congestion_marked=packet.PDS_header.RUOD_ack_header.flags.m;
        ack.packet=sample; ack.service_time_quanta=feedback.service_time;
        if (packet.has_receive_timestamp) ack.first_bit_arrival_ns=packet.receive_time_ns;
        ack.retransmit_flag=packet.PDS_header.RUOD_ack_header.flags.retx;
        ack.receiver_window_penalty=feedback.receiver_window_penalty; ack.restore_window=feedback.restore_window;
        state.inflight_contribution-=static_cast<int64_t>(ack.newly_received_bytes);
        state.controller->on_ack(ack,clock_.now());
        record("nscc_received_bytes",ack.newly_received_bytes);
        record("nscc_window",state.controller->state().congestion_window);
        if (wake_) wake_();
    }
    void negative_acknowledged(const Connection& connection,uint32_t size,const PDStoNET_pkt& packet,
                                std::optional<NsccTransmitSample> sample) override {
        auto& state=source(connection);
        const auto code=packet.PDS_header.nack_header.nack_code;
        const auto reason=code==UET_TRIMMED?NsccNackReason::Trimmed:
            code==UET_TRIMMED_LASTHOP?NsccNackReason::TrimmedLastHop:NsccNackReason::Other;
        state.inflight_contribution-=size;
        state.controller->on_nack(size,sample,packet.PDS_header.nack_header.flags.retx,reason,false,clock_.now());
        if (wake_) wake_();
    }
    void negative_acknowledgment_event(const Connection&,const PDStoNET_pkt& packet) override {
        record("nscc_nack",packet.PDS_header.nack_header.nack_code);
    }
    void inferred_loss(const Connection& connection,uint32_t size) override {
        auto& state=source(connection);
        state.inflight_contribution-=size;
        state.controller->on_inferred_loss(size,clock_.now());
        record("nscc_inferred_loss",size);
        if (wake_) wake_();
    }
    void canceled_unsent_retry(const Connection& connection,uint32_t size) override {
        auto& state=source(connection);
        state.inflight_contribution+=size;
        state.controller->on_send(size,clock_.now()); // Restore bytes only; no transmission or window increase.
        record("nscc_canceled_loss",size);
    }
    void received(const Connection& connection,const PDStoNET_pkt& packet,bool duplicate=false) override {
        // Called only after PDS's window/order/duplicate validation succeeds.
        auto& state=receivers_[connection];
        if (!duplicate) state.accepted_bytes+=packet.nominal_packet_size;
        state.samples[packet.PDS_header.RUOD_req_header.psn]=
            {packet.receive_time_ns,packet.wire_entropy,packet.network_ecn==3,bool(packet.PDS_header.RUOD_req_header.flags.retx)};
    }
    void decorate_ack(const Connection& connection,uint32_t psn,PDStoNET_pkt& packet) override {
        const auto found=receivers_.find(connection);
        if (found==receivers_.end()) return; // Control-only PDC has no data counter.
        const auto& state=found->second;
        auto& feedback=packet.congestion_ack;
        packet.PDS_header.RUOD_ack_header.type=ACK_CC;
        feedback.received_byte_units=ReceivedByteCounter::encode(state.accepted_bytes);
        feedback.out_of_order_count=0xffff; // Optional estimate deliberately not implemented.
        if (const auto sample=state.samples.find(psn);sample!=state.samples.end()) {
            packet.PDS_header.RUOD_ack_header.flags.m=sample->second.marked;
            packet.PDS_header.RUOD_ack_header.flags.retx=sample->second.retransmitted;
            packet.wire_entropy=sample->second.entropy;
            feedback.service_time=static_cast<uint16_t>(std::min<uint64_t>(0xffff,(clock_.now()-sample->second.arrival_ns)/128));
        }
    }
    void receive_cleared(const Connection& connection,uint32_t clear_through) override {
        const auto found=receivers_.find(connection);
        if (found==receivers_.end()) return;
        auto& samples=found->second.samples;
        for (auto entry=samples.begin();entry!=samples.end();)
            if (clear_through-entry->first<0x80000000u) entry=samples.erase(entry); else ++entry;
    }
    void closed(const Connection& connection) override {
        receivers_.erase(connection);
        const auto found=sources_.find(connection);
        if (found==sources_.end()) return;
        auto controller=found->second.controller;
        controller->retire_inflight(found->second.inflight_contribution,clock_.now());
        sources_.erase(found);
        const auto key=controller_key(connection);
        // The map and this local variable are the only remaining owners.
        if (controller.use_count()==2) controllers_.erase(key);
        if (wake_) wake_();
    }
    size_t congestion_context_count() const { return controllers_.size(); }
    size_t source_connection_count() const { return sources_.size(); }
    size_t receive_sample_count() const {
        size_t count=0; for (const auto& item:receivers_) count+=item.second.samples.size(); return count;
    }
    const NsccState& state(const Connection& connection) const { return sources_.at(connection).controller->state(); }
private:
    using ControllerKey=std::tuple<uint32_t,bool,uint16_t,uint32_t>;
    struct Source {
        std::shared_ptr<NsccController> controller;
        ReceivedByteCounter byte_counter;
        int64_t inflight_contribution=0;
        uint16_t fixed_entropy=0;
    };
    struct ReceiveSample { uint64_t arrival_ns; uint16_t entropy; bool marked,retransmitted; };
    struct Receiver { uint64_t accepted_bytes=0; std::map<uint32_t,ReceiveSample> samples; };
    NsccConfig config_;
    Runtime::IClock& clock_;
    std::function<void()> wake_;
    NetworkLayer::WireOptions wire_;
    Runtime::Trace* trace_;
    uint32_t node_;
    uint16_t next_entropy_=1;
    std::map<ControllerKey,std::shared_ptr<NsccController>> controllers_;
    std::map<Connection,Source> sources_;
    std::map<Connection,Receiver> receivers_;

    static ControllerKey controller_key(const Connection& connection) {
        return {connection.peer,connection.ordered,connection.ordered?connection.local_pdc:uint16_t{0},
            connection.ordered?connection.starting_psn:0};
    }
    Source& source(const Connection& connection) {
        const auto found=sources_.find(connection);
        if (found!=sources_.end()) return found->second;
        auto& controller=controllers_[controller_key(connection)];
        if (!controller) controller=std::make_shared<NsccController>(config_,clock_.now());
        Source state; state.controller=controller; state.fixed_entropy=next_entropy_++;
        return sources_.emplace(connection,std::move(state)).first->second;
    }
    void record(const char* event,uint64_t value) { if (trace_) trace_->record(node_,event,value); }
};
} // namespace UET::CMS
