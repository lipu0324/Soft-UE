#include "PDC.hpp"
#include <algorithm>

bool PDC::beginTransmitIncarnation() {
    transmit_incarnation_=0;
    if (!runtime_) return true;
    if (runtime_->rto_ns>UET::Runtime::kMaximumInitialRtoNs) return false;
    if (runtime_->next_pdc_incarnation==UINT64_MAX) return false;
    transmit_incarnation_=++runtime_->next_pdc_incarnation;
    return true;
}

void PDC::tagTransmission(PDStoNET_pkt& packet,uint32_t sequence,UET::Runtime::TransmitKind kind,
                          uint16_t attempt,uint16_t opaque) {
    const bool synchronizing=packet.PDS_type==RUOD_req_header?packet.PDS_header.RUOD_req_header.flags.syn:
        packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.flags.syn;
    packet.transmit_identity.reset();
    const bool actual_timing=waitsForTransmitNotification();
    if (actual_timing)
        packet.transmit_identity=UET::Runtime::TransmitIdentity{SPDCID,start_psn,transmit_incarnation_,sequence,attempt,opaque,kind,synchronizing};
    if (kind!=UET::Runtime::TransmitKind::Probe) {
        auto& metadata=tx_pkt_map[sequence];
        metadata.awaiting_transmission=actual_timing;
        metadata.transmit_time_valid=!actual_timing;
        if (runtime_ && !actual_timing) metadata.last_transmit_time=runtime_->clock.now();
    }
}

bool PDC::notifyTransmit(const UET::Runtime::TransmitNotification& notification) {
    const auto& identity=notification.identity;
    if (!runtime_ || !transmit_incarnation_ || identity.incarnation!=transmit_incarnation_ ||
        identity.local_pdc!=SPDCID || identity.connection_start_psn!=start_psn ||
        notification.time_ns>runtime_->clock.now()) return false;
    const bool started=notification.outcome==UET::Runtime::TransmitOutcome::Started;
    if (identity.kind==UET::Runtime::TransmitKind::Probe) {
        if (!outstanding_probe_ || !outstanding_probe_->awaiting_transmission ||
            outstanding_probe_->opaque!=identity.opaque || outstanding_probe_->retries!=identity.attempt) return false;
        auto& probe=*outstanding_probe_;
        probe.sent_at=notification.time_ns; probe.transmit_time_valid=started; probe.awaiting_transmission=false;
        armProbeWake(UET::Runtime::retransmission_timeout_ns(runtime_->rto_ns,probe.retries));
        return true;
    }
    const auto found=tx_pkt_map.find(identity.sequence);
    if (found==tx_pkt_map.end() || !tx_pkt_buffer.count(identity.sequence) ||
        found->second.retry_cnt!=identity.attempt || !found->second.awaiting_transmission) return false;
    auto& metadata=found->second;
    metadata.last_transmit_time=notification.time_ns;
    metadata.transmit_time_valid=started; metadata.awaiting_transmission=false;
    // A locally rejected frame gets a retry timer but no fabricated RTT sample.
    // Accepted, queued frames consume no RTO before their first-bit departure.
    stopPacketTimer(identity.sequence);
    if (rtoEnabled()) startPacketTimer(identity.sequence,metadata.timeout_retry_count);
    // §3.5.8.3 starts SYN safety from the most recent *lost* SYN attempt.
    // Record this attempt's MAC time now; txRto extends safety only if loss
    // is inferred later. A successful retry must not extend the safety wait.
    return true;
}
