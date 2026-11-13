#include "PDC.hpp"

bool PDC::queueAcknowledgment(uint32_t sequence,PDStoNET_pkt acknowledgment) {
    const auto emit=[this](const PDStoNET_pkt& ready) {
        if (public_net_queue) return public_net_queue->push(ready);
        tx_pkt_q.push(ready); return true;
    };
    if (!runtime_ || !runtime_->standard_wire || mode!=ROD) return emit(acknowledgment);
    if (!next_ordered_ack_psn_) next_ordered_ack_psn_=start_psn;
    if (sequence-*next_ordered_ack_psn_>=0x80000000u) {
        // §3.5.21.1 permits recovery of an older guaranteed ACK while later
        // requests continue. Replays do not consume a second ordering slot.
        return emit(acknowledgment);
    }
    // Retain the original trigger's entropy/CE/arrival time. A query for an
    // already-ready response cannot move it ahead of an unfinished earlier
    // SES request. The receive PSN window bounds the number of held entries.
    pending_ordered_acknowledgments_.try_emplace(sequence,std::move(acknowledgment));
    while (true) {
        const auto next=pending_ordered_acknowledgments_.find(*next_ordered_ack_psn_);
        if (next==pending_ordered_acknowledgments_.end()) return true;
        if (!emit(next->second)) return false;
        pending_ordered_acknowledgments_.erase(next);
        ++*next_ordered_ack_psn_; // Unsigned wrap is part of the 32-bit PSN space.
    }
}
