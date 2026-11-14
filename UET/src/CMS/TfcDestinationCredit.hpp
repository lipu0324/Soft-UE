#pragma once
#include "TfcCredit.hpp"
#include <map>

namespace UET::CMS {

// A single destination CCC's reserved transport-buffer budget. This is a
// deterministic accounting primitive, not a PDS adapter or an enabled policy.
// The caller must reserve capacity_bytes from its host-wide pool before
// creating this object, and supply duplicate-filtered PDS receive ownership.
class TfcDestinationCredit {
public:
    using BufferLease=uint64_t;

    TfcDestinationCredit(TfcSourceConfig geometry,uint64_t capacity_bytes)
        : cost_model_(geometry),capacity_bytes_(capacity_bytes),
          maximum_packet_bytes_(cost_model_.packet_credit_bytes(geometry.payload_mtu_bytes)),
          promised_credit_bytes_(geometry.initial_credit_bytes) {
        // §3.6.15: any positive credit permits a whole MTU packet, independent
        // of its size. Preserve one maximum-packet overshoot reserve in
        // addition to initial credit; it cannot be lent to another CCC.
        // Keeping the whole reservation below the 24-bit counter half-space
        // also bounds the number of unobserved credit grants in flight.
        if (capacity_bytes_>=(uint64_t{1}<<31) ||
            geometry.initial_credit_bytes>static_cast<int64_t>(capacity_bytes_) ||
            maximum_packet_bytes_>capacity_bytes_-geometry.initial_credit_bytes)
            throw std::invalid_argument("TFC destination budget cannot cover initial credit and an MTU overshoot");
    }

    uint64_t capacity_bytes() const { return capacity_bytes_; }
    uint64_t buffered_bytes() const { return buffered_bytes_; }
    uint64_t granted_bytes() const { return granted_bytes_; }
    uint64_t requested_bytes() const { return requested_bytes_; }
    int64_t promised_credit_bytes() const { return promised_credit_bytes_; }
    size_t buffer_count() const { return buffers_.size(); }
    uint32_t cumulative_credit_units() const {
        return static_cast<uint32_t>((granted_bytes_>>8)&0xffffff);
    }

    void observe_credit_target(uint32_t cumulative_target_units) {
        if (cumulative_target_units>0xffffff)
            throw std::invalid_argument("TFC credit target exceeds 24 bits");
        auto next_counter=target_counter_;
        const auto additional_bytes=next_counter.acknowledge(cumulative_target_units);
        if (additional_bytes>std::numeric_limits<uint64_t>::max()-requested_bytes_)
            throw std::overflow_error("TFC cumulative demand exhausted byte accounting");
        requested_bytes_+=additional_bytes;
        target_counter_=next_counter;
    }

    bool can_accept_new_packet(uint64_t payload_bytes) const {
        const auto consumed_bytes=cost_model_.packet_credit_bytes(payload_bytes);
        const auto remaining_credit=promised_credit_bytes_-consumed_bytes;
        // Requests may arrive in a different order from transmission. Test
        // aggregate entitlement rather than requiring the receive-side
        // balance to be positive for each particular arriving packet.
        return consumed_bytes<=capacity_bytes_-buffered_bytes_ &&
            remaining_credit>-static_cast<int64_t>(maximum_packet_bytes_);
    }

    BufferLease accept_new_packet(uint64_t payload_bytes) {
        const auto consumed_bytes=cost_model_.packet_credit_bytes(payload_bytes);
        if (!can_accept_new_packet(payload_bytes))
            throw std::length_error("packet exceeds the CCC's allocated TFC buffer entitlement");
        if (next_buffer_lease_==std::numeric_limits<BufferLease>::max())
            throw std::overflow_error("TFC buffer lease namespace exhausted");
        const auto lease=next_buffer_lease_;
        // Allocate before committing counters, preserving state on allocation
        // failure. Local leases never wrap into a delayed release callback.
        buffers_.emplace(lease,consumed_bytes);
        ++next_buffer_lease_;
        buffered_bytes_+=consumed_bytes;
        promised_credit_bytes_-=consumed_bytes;
        return lease;
    }

    bool release_packet(BufferLease lease) {
        const auto found=buffers_.find(lease);
        if (found==buffers_.end()) return false; // Duplicate/stale local release.
        buffered_bytes_-=found->second;
        buffers_.erase(found);
        return true;
    }

    uint64_t allocate_credit() {
        // §§3.6.15/3.6.15.2 leave the destination's allocation policy open.
        // Simulator policy: satisfy observed demand eagerly, but never lend
        // the MTU reserve or storage still owned by an accepted packet.
        // Signed arithmetic also repays a legal source overshoot before a
        // grant exposes more positive balance at that source.
        const auto uncommitted_bytes=static_cast<int64_t>(capacity_bytes_)-
            static_cast<int64_t>(maximum_packet_bytes_)-static_cast<int64_t>(buffered_bytes_)-
            promised_credit_bytes_;
        if (uncommitted_bytes<=0 || requested_bytes_<=granted_bytes_) return 0;
        const auto available_bytes=static_cast<uint64_t>(uncommitted_bytes)&~uint64_t{255};
        const auto additional_bytes=std::min(available_bytes,requested_bytes_-granted_bytes_);
        if (additional_bytes>std::numeric_limits<uint64_t>::max()-granted_bytes_)
            throw std::overflow_error("TFC cumulative grants exhausted byte accounting");
        granted_bytes_+=additional_bytes;
        promised_credit_bytes_+=static_cast<int64_t>(additional_bytes);
        return additional_bytes;
    }

private:
    const TfcSourceCredit cost_model_;
    const uint64_t capacity_bytes_;
    const uint32_t maximum_packet_bytes_;
    int64_t promised_credit_bytes_;
    uint64_t buffered_bytes_=0,granted_bytes_=0,requested_bytes_=0;
    ReceivedByteCounter target_counter_;
    BufferLease next_buffer_lease_=1;
    std::map<BufferLease,uint32_t> buffers_;
};

} // namespace UET::CMS
