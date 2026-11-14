#include "PDC.hpp"

bool PDC::cancelNegativeAcknowledgmentRetry(uint32_t sequence) {
    const auto pending=negative_acknowledgment_timers_.find(sequence);
    if (pending==negative_acknowledgment_timers_.end()) return false;
    if (runtime_) runtime_->timers.cancel(pending->second);
    negative_acknowledgment_timers_.erase(pending);
    return true;
}

void PDC::scheduleNegativeAcknowledgmentRetry(uint32_t sequence,UET::Runtime::Time delay_ns) {
    const auto metadata=tx_pkt_map.find(sequence);
    if (metadata==tx_pkt_map.end() || !tx_pkt_buffer.count(sequence) || metadata->second.awaiting_transmission ||
        negative_acknowledgment_timers_.count(sequence) || admission_deferred_retries_.count(sequence)) return;
    if (!runtime_) { retryPacket(sequence,RetryCause::NegativeAcknowledgment); return; }
    // A duplicate NACK neither restarts this delay nor consumes another retry.
    // Once it expires, the ordinary PDS admission path still owns the retry.
    const auto when=UET::Runtime::add_time(runtime_->clock.now(),delay_ns);
    stopPacketTimer(sequence);
    const auto incarnation=transmit_incarnation_;
    const std::weak_ptr<int> lifetime=lifetime_guard_;
    negative_acknowledgment_timers_[sequence]=runtime_->timers.at(when,[this,lifetime,incarnation,sequence] {
        if (lifetime.expired() || incarnation!=transmit_incarnation_) return;
        negative_acknowledgment_timers_.erase(sequence);
        if (!tx_pkt_buffer.count(sequence) || !tx_pkt_map.count(sequence)) return;
        admission_deferred_retries_.emplace(sequence,RetryCause::NegativeAcknowledgment);
        if (runtime_->wake) runtime_->wake();
    });
}
