#include "PDC.hpp"
#include <algorithm>

bool PDC::needsWindowProbe() const {
    return runtime_ && runtime_->standard_wire && runtime_->enable_automatic_window_probes && !SYN && state==ESTABLISHED &&
        !tx_req_q.empty() && !peerWindowAllows(tx_cur_psn) && !outstanding_probe_ &&
        runtime_->clock.now()>=next_window_probe_time_;
}

void PDC::resetProbe() {
    if (runtime_ && probe_timer_) runtime_->timers.cancel(probe_timer_);
    probe_timer_=0; outstanding_probe_.reset(); probe_due_=false; next_window_probe_time_=0;
}

void PDC::armProbeWake(UET::Runtime::Time delay) {
    if (probe_timer_) runtime_->timers.cancel(probe_timer_);
    std::weak_ptr<int> lifetime=lifetime_guard_;
    probe_timer_=runtime_->timers.at(UET::Runtime::add_time(runtime_->clock.now(),delay),[this,lifetime] {
        if (lifetime.expired()) return;
        probe_timer_=0;
        probe_due_=outstanding_probe_.has_value();
        if (runtime_->wake) runtime_->wake();
    });
}

bool PDC::requestProbe(uint32_t selective_base) {
    if (!runtime_ || !runtime_->standard_wire || SYN || !DPDCID || state!=ESTABLISHED || outstanding_probe_) return false;
    // §3.5.16.5: opaque is not a PSN; no sequence, unacknowledged count or
    // congestion byte budget is allocated. Zero is a legal opaque on wrap.
    outstanding_probe_=ProbeAttempt{++runtime_->next_probe_opaque,selective_base&~uint32_t{7},runtime_->clock.now(),0};
    sendProbeAttempt();
    if (runtime_->wake) runtime_->wake();
    return true;
}

void PDC::sendProbeAttempt() {
    auto& probe=*outstanding_probe_;
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header; packet.src_fep=src_fep; packet.dst_fep=dst_fep;
    auto& control=packet.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=Probe; control.flags.ar=1; control.flags.retx=probe.retries!=0;
    control.psn=0; control.spdcid=SPDCID; control.dpdcid=DPDCID;
    control.probe_opaque=probe.opaque; control.payload=probe.selective_base;
    decorateControl(packet);
    tagTransmission(packet,0,UET::Runtime::TransmitKind::Probe,probe.retries,probe.opaque);
    probe.awaiting_transmission=waitsForTransmitNotification();
    probe.transmit_time_valid=!probe.awaiting_transmission;
    probe.sent_at=runtime_->clock.now();
    if (public_net_queue) public_net_queue->push(packet); else tx_pkt_q.push(std::move(packet));
    // Probe polling/backoff is a bounded simulator policy, not a new PSN RTO.
    if (!waitsForTransmitNotification()) armProbeWake(UET::Runtime::retransmission_timeout_ns(runtime_->rto_ns,probe.retries));
}

void PDC::progressProbe() {
    if (outstanding_probe_ && probe_due_) {
        probe_due_=false;
        if (!UET::Runtime::retry_permitted(outstanding_probe_->retries,runtime_->maximum_packet_retries)) {
            resetProbe();
            // A failed diagnostic probe alone does not fail successful data.
            // An unreachable peer that prevents queued data from advancing
            // must, however, eventually terminate rather than wait forever.
            if (!tx_req_q.empty() && !peerWindowAllows(tx_cur_psn)) {
                failure_reason_=UET::Runtime::PdcFailureReason::RetryExhausted; close_error=true;
            }
        } else {
            outstanding_probe_->retries=UET::Runtime::next_retry_count(outstanding_probe_->retries);
            sendProbeAttempt();
        }
    } else if (needsWindowProbe()) requestProbe(clear_psn+1);
}

void PDC::receiveProbeAcknowledgment(const PDStoNET_pkt& packet) {
    const auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
    if (!outstanding_probe_ || acknowledgment.flags.req || acknowledgment.next_hdr!=UET_HDR_NONE ||
        static_cast<uint16_t>(acknowledgment.ack_psn_off)!=outstanding_probe_->opaque ||
        (tx_cur_psn-1)-acknowledgment.cack_psn>=0x80000000u) return;
    const auto probe=*outstanding_probe_;
    resetProbe();
    processPeerAcknowledgment(packet);
    if (runtime_->congestion_control)
        runtime_->congestion_control->acknowledged(congestionConnection(),packet,
            probe.transmit_time_valid?std::optional<UET::CMS::NsccTransmitSample>{{probe.sent_at,probe.retries}}:std::nullopt);
    // §3.5.11.8.7: only ACK_PSN is invalid in a Probe reply. CACK, SACK,
    // MP_RANGE and recognized congestion state still describe real data.
    processDeliveryAcknowledgment(packet);
    processSemanticAcknowledgment(packet);
    updateTxPsnTracker(clear_psn,0,acknowledgment.cack_psn);
    if (needsWindowProbe()) {
        const auto delay=std::max<uint64_t>(1,runtime_->rto_ns);
        next_window_probe_time_=UET::Runtime::add_time(runtime_->clock.now(),delay);
        armProbeWake(delay); // Pace an unchanged window; never poll at zero time.
    }
}

void PDC::receiveProbe(const PDStoNET_pkt& packet) {
    const auto& control=packet.PDS_header.RUOD_cp_header;
    if (!control.flags.ar || control.flags.syn || control.psn) return;
    PDStoNET_pkt response{}; response.PDS_type=RUOD_ack_header; response.src_fep=src_fep; response.dst_fep=dst_fep;
    auto& acknowledgment=response.PDS_header.RUOD_ack_header;
    acknowledgment.type=ACK_CC; acknowledgment.next_hdr=UET_HDR_NONE;
    acknowledgment.flags.p=1; acknowledgment.cack_psn=cack_psn;
    acknowledgment.ack_psn_off=static_cast<int16_t>(control.probe_opaque);
    acknowledgment.spdcid=SPDCID; acknowledgment.dpdcid=DPDCID;
    // §3.5.16.5 gives Probe's specific base rule: max(payload,CACK), using
    // serial comparison. Unlike the normal per-packet base it can be unaligned
    // when CACK wins; this specification inconsistency is documented.
    const uint32_t requested_distance=control.payload-cack_psn;
    const uint32_t selective_base=requested_distance>=0x80000000u?cack_psn:control.payload;
    const uint32_t offset=selective_base-cack_psn;
    if (offset>INT16_MAX) return; // Cannot represent this request in ACK_CC's signed offset.
    if (runtime_ && runtime_->congestion_control)
        runtime_->congestion_control->decorate_ack(congestionConnection(),0,response);
    response.congestion_ack.mpr=advertised_mpr_;
    response.congestion_ack.sack_psn_offset=static_cast<int16_t>(offset);
    const auto include=[&](uint32_t sequence) {
        const uint32_t bit=sequence-selective_base;
        if (bit<64) response.congestion_ack.sack_bitmap|=uint64_t{1}<<bit;
    };
    if (selective_base==cack_psn && cack_psn-start_psn<0x80000000u) include(cack_psn);
    for (const auto sequence:completed_rx_psns_) include(sequence);
    for (const auto& cached:tx_ack_buffer) include(cached.first);
    decorateAcknowledgmentNetwork(0,&packet,response);
    if (public_net_queue) public_net_queue->push(response); else tx_pkt_q.push(std::move(response));
}
