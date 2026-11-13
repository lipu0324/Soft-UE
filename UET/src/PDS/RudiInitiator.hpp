#pragma once
#include "../Transport_Layer.hpp"
#include "../Runtime/Runtime.hpp"
#include "NegativeAcknowledgment.hpp"
#include <optional>

namespace UET::PDS {
// §3.5.23: all RUDI reliability belongs to the initiator. This helper is
// owned by PDS_Manager; it allocates neither a PDC nor a target recovery map.
// SES remains responsible for selecting idempotent operations and checking
// memory. Emit queues one packet; it must never synchronously re-enter PDS.
class RudiInitiator {
public:
    struct Result {
        uint32_t packet_id,peer,job,request_offset;
        uint16_t message_id;
        bool timed_out;
        SEStoPDS_pkt semantic_response;
    };
    using Emit=std::function<bool(const PDStoNET_pkt&)>;
    using Complete=std::function<void(Result)>;
    RudiInitiator(Runtime::Services& services,Emit emit,Complete complete)
        : services_(services),emit_(std::move(emit)),complete_(std::move(complete)) {}
    ~RudiInitiator() { clear(); }
    RudiInitiator(const RudiInitiator&)=delete;
    RudiInitiator& operator=(const RudiInitiator&)=delete;

    std::optional<uint32_t> submit(const SES_PDS_req& request) {
        if (!lifetime_ || request.mode!=RUDI || request.pkt.bth_type!=Standard_Header || !request.src_fep || !request.dst_fep ||
            pending_.size()>=services_.rudi_packet_limit || services_.next_rudi_packet_id>UINT32_MAX) return {};
        const auto packet_id=static_cast<uint32_t>(services_.next_rudi_packet_id++);
        Outstanding outstanding{};
        outstanding.packet.src_fep=request.src_fep; outstanding.packet.dst_fep=request.dst_fep;
        outstanding.packet.PDS_type=RUDI_header;
        outstanding.packet.PDS_header.RUDI_header={RUDI_REQ,request.next_hdr,{0,0},packet_id};
        outstanding.packet.SESpkt=request.pkt;
        outstanding.packet.wire_entropy=services_.default_wire_entropy;
        outstanding.packet.network_ecn=2; // ECT, without UET-CC admission (§3.5.23.1).
        outstanding.packet.local_tx_handle=request.tx_pkt_handle;
        pending_.emplace(packet_id,std::move(outstanding));
        // Backpressure keeps a bounded pending packet, with no premature RTO.
        send_pending(packet_id,false);
        return packet_id;
    }
    size_t outstanding_packets() const { return pending_.size(); }
    bool active_attempt(const Runtime::TransmitIdentity& identity) const {
        const auto found=pending_.find(identity.sequence);
        return identity.kind==Runtime::TransmitKind::RudiRequest && found!=pending_.end() &&
            found->second.awaiting_departure && found->second.attempt==identity.attempt;
    }
    bool notify_transmit(const Runtime::TransmitNotification& notification) {
        if (!active_attempt(notification.identity) || notification.time_ns>services_.clock.now()) return false;
        auto& outstanding=pending_.at(notification.identity.sequence);
        outstanding.awaiting_departure=false;
        // The NIC first-bit boundary starts the timer. A WouldBlock before
        // that boundary consumes neither a retry nor its timeout budget.
        const auto duration=Runtime::retransmission_timeout_ns(services_.rto_ns,outstanding.timeout_retries);
        const auto remaining=UINT64_MAX-notification.time_ns;
        schedule(notification.identity.sequence,std::max(services_.clock.now(),
            notification.time_ns+std::min(duration,remaining)),RetryCause::Timeout);
        return true;
    }
    bool receive(const PDStoNET_pkt& received) {
        const bool response=received.PDS_type==RUDI_header && received.PDS_header.RUDI_header.type==RUDI_RESP;
        const bool negative=received.PDS_type==nack_header && received.PDS_header.nack_header.flags.nt;
        if (!response && !negative) return false;
        const auto packet_id=response?received.PDS_header.RUDI_header.pkt_id:received.PDS_header.nack_header.nack_pkt_id;
        const auto found=pending_.find(packet_id);
        if (found==pending_.end()) return false;
        auto& outstanding=found->second;
        if (received.src_fep!=outstanding.packet.dst_fep || received.dst_fep!=outstanding.packet.src_fep) return false;
        if (received.trimmed || negative) {
            if (outstanding.awaiting_departure || outstanding.retry_ready || outstanding.cause==RetryCause::Negative) return false;
            Runtime::Time delay=0;
            if (negative) {
                const auto policy=negative_acknowledgment_policy(received.PDS_header.nack_header.nack_code);
                // PDC establishment/window/fatal actions have no RUDI meaning.
                // Recognized resource/trim indications only accelerate replay.
                if (!policy || policy->action!=NegativeAcknowledgmentAction::Retransmit) return false;
                delay=services_.nack_retransmission_delays_ns[policy->delay_group];
            }
            schedule(packet_id,Runtime::add_time(services_.clock.now(),delay),RetryCause::Negative);
            return true;
        }
        if (!matches_semantics(outstanding,received.SESpkt)) return false;
        auto result=make_result(packet_id,outstanding,false);
        result.semantic_response=received.SESpkt;
        erase(found); // Release transport ownership before the queued SES upcall.
        complete_(std::move(result));
        return true;
    }
    bool progress() {
        bool worked=false;
        // Completion may enqueue work, but the owning manager must not re-enter
        // this method from the callback. Iterate stable IDs, never peer PSNs.
        std::vector<uint32_t> ready;
        for (const auto& entry:pending_)
            if (!entry.second.attempt || entry.second.retry_ready) ready.push_back(entry.first);
        for (const auto packet_id:ready) {
            auto found=pending_.find(packet_id);
            if (found==pending_.end()) continue;
            auto& outstanding=found->second;
            const bool retry=outstanding.attempt!=0;
            if (retry && !Runtime::retry_permitted(outstanding.retries,services_.maximum_packet_retries)) {
                auto result=make_result(packet_id,outstanding,true); erase(found); complete_(std::move(result)); worked=true;
            } else worked=send_pending(packet_id,retry) || worked;
        }
        return worked;
    }
    void cancel_message(uint32_t peer,uint32_t job,uint16_t message) {
        for (auto found=pending_.begin();found!=pending_.end();) {
            const auto& header=found->second.packet.SESpkt.bth_header.Standard_Header;
            if (found->second.packet.dst_fep==peer && header.job_id==job && header.msg_id==message)
                found=erase(found); else ++found;
        }
    }
    void clear() {
        lifetime_.reset();
        for (const auto& entry:pending_) if (entry.second.timer) services_.timers.cancel(entry.second.timer);
        pending_.clear();
    }
private:
    enum class RetryCause { None, Timeout, Negative };
    struct Outstanding {
        PDStoNET_pkt packet;
        Runtime::TimerId timer=0;
        uint64_t attempt=0,retries=0,timeout_retries=0;
        RetryCause cause=RetryCause::None;
        bool awaiting_departure=false,retry_ready=false;
    };
    Runtime::Services& services_;
    Emit emit_;
    Complete complete_;
    std::map<uint32_t,Outstanding> pending_;
    std::shared_ptr<int> lifetime_=std::make_shared<int>(0);

    std::map<uint32_t,Outstanding>::iterator erase(std::map<uint32_t,Outstanding>::iterator found) {
        if (found->second.timer) services_.timers.cancel(found->second.timer);
        return pending_.erase(found);
    }
    static Result make_result(uint32_t packet_id,const Outstanding& outstanding,bool timed_out) {
        const auto& header=outstanding.packet.SESpkt.bth_header.Standard_Header;
        return {packet_id,outstanding.packet.dst_fep,header.job_id,header.som?0:header.diff.som_false.message_offset,
            header.msg_id,timed_out,{}};
    }
    bool matches_semantics(const Outstanding& outstanding,const SEStoPDS_pkt& response) const {
        const auto& request=outstanding.packet.SESpkt.bth_header.Standard_Header;
        if (response.bth_type==Semantic_Response_Header) {
            const auto& header=response.bth_header.Semantic_Response_Header;
            return !header.version && header.opcode<=1 && header.job_id==request.job_id && header.message_id==request.msg_id &&
                (request.opcode!=2 || header.return_code!=1); // A successful READ needs actual result data.
        }
        if (response.bth_type!=Semantic_Response_with_Data_Header || request.opcode!=2) return false;
        const auto& header=response.bth_header.Semantic_Response_with_Data_Header;
        const uint32_t offset=request.som?0:request.diff.som_false.message_offset;
        return !header.version && header.opcode==2 && header.job_id==request.job_id && header.read_request_msg_id==request.msg_id &&
            offset<=request.request_length && header.message_offset==offset && header.payload_length==response.payload.size() &&
            header.payload_length==std::min(services_.semantic_payload_mtu,request.request_length-offset);
    }
    void schedule(uint32_t packet_id,Runtime::Time deadline,RetryCause cause) {
        auto& outstanding=pending_.at(packet_id);
        if (outstanding.timer) services_.timers.cancel(outstanding.timer);
        outstanding.cause=cause;
        const auto attempt=outstanding.attempt;
        const std::weak_ptr<int> lifetime=lifetime_;
        outstanding.timer=services_.timers.at(deadline,[this,lifetime,packet_id,attempt] {
            if (lifetime.expired()) return;
            const auto found=pending_.find(packet_id);
            if (found==pending_.end() || found->second.attempt!=attempt) return;
            found->second.timer=0; found->second.retry_ready=true;
            if (services_.wake) services_.wake();
        });
    }
    bool send_pending(uint32_t packet_id,bool retry) {
        auto& outstanding=pending_.at(packet_id);
        auto packet=outstanding.packet;
        const auto attempt=Runtime::next_retry_count(outstanding.attempt);
        packet.PDS_header.RUDI_header.flags.retx=retry;
        packet.transmit_identity=Runtime::TransmitIdentity{UINT16_MAX,0,0,packet_id,attempt,0,Runtime::TransmitKind::RudiRequest,false};
        if (!emit_(packet)) return false;
        if (retry) {
            outstanding.retries=Runtime::next_retry_count(outstanding.retries);
            if (outstanding.cause==RetryCause::Timeout)
                outstanding.timeout_retries=Runtime::next_retry_count(outstanding.timeout_retries);
        }
        outstanding.attempt=attempt; outstanding.awaiting_departure=true; outstanding.retry_ready=false;
        outstanding.cause=RetryCause::None;
        return true;
    }
};
} // namespace UET::PDS
