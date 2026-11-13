#pragma once
#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>

namespace UET::PDS {
// The peer's Maximum PSN Range (MP_RANGE), UE 1.1 §3.5.11.13, limits our
// transmissions relative to its CACK. It is independent of both our receive
// tracking capacity and CMS's byte congestion window.
class PeerSequenceWindow {
public:
    static constexpr uint32_t MaximumRange=255*128;
    explicit PeerSequenceWindow(uint32_t initial_psn,uint32_t zero_override=0,uint32_t default_mpr=8)
        :cumulative_ack_(initial_psn-1),zero_override_(zero_override),initial_range_(std::max(1u,default_mpr)*128) {
        if (zero_override>MaximumRange || default_mpr>255) throw std::invalid_argument("MPR configuration exceeds PSN range");
    }
    static bool after(uint32_t sequence,uint32_t previous) {
        const uint32_t distance=sequence-previous;
        return distance && distance<0x80000000u;
    }
    // Caller validates the CACK against transmitted PSNs before observing it.
    // An ordinary ACK advances the anchor without changing the advertised MPR.
    bool observe(uint32_t cumulative_ack,std::optional<uint8_t> encoded_mpr={}) {
        if (after(cumulative_ack,cumulative_ack_)) cumulative_ack_=cumulative_ack;
        if (!encoded_mpr || (last_mpr_ack_ && !after(cumulative_ack,*last_mpr_ack_))) return false;
        const auto range=*encoded_mpr?uint32_t{*encoded_mpr}*128:zero_override_;
        if (!range) {
            // §3.5.11.13 ignores the *range*, not just this advertisement.
            // A peer with zero override may use zero only until its first
            // nonzero advertisement. Reject a later invalid zero conservatively.
            if (advertised_range_) return false;
            range_ignored_=true; last_mpr_ack_=cumulative_ack; return true;
        }
        range_ignored_=false;
        advertised_range_=range; last_mpr_ack_=cumulative_ack;
        return true;
    }
    bool allows(uint32_t sequence) const {
        const auto range=effective_range();
        if (!range) return true;
        const uint32_t distance=sequence-cumulative_ack_;
        // Retries at/below CACK remain legal. Only the forward serial interval
        // beyond CACK+MP_RANGE is closed, including when the sequence wraps.
        return distance>=0x80000000u || distance<=*range;
    }
    uint32_t cumulative_ack() const { return cumulative_ack_; }
    std::optional<uint32_t> advertised_range() const { return advertised_range_; }
    std::optional<uint32_t> effective_range() const {
        return range_ignored_?std::nullopt:std::optional<uint32_t>{advertised_range_.value_or(initial_range_)};
    }
private:
    uint32_t cumulative_ack_,zero_override_,initial_range_;
    bool range_ignored_=false;
    std::optional<uint32_t> advertised_range_,last_mpr_ack_;
};
} // namespace UET::PDS
