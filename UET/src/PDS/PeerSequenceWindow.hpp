#pragma once
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
    explicit PeerSequenceWindow(uint32_t initial_psn,uint32_t zero_override=0)
        :cumulative_ack_(initial_psn-1),zero_override_(zero_override) {
        if (zero_override>MaximumRange) throw std::invalid_argument("MPR zero override exceeds PSN range");
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
        if (!range) return false; // Override_MPR_Zero_Value=0 means ignore the zero encoding.
        advertised_range_=range; last_mpr_ack_=cumulative_ack;
        return true;
    }
    bool allows(uint32_t sequence) const {
        if (!advertised_range_) return true; // The provisioned local send bound still applies.
        const uint32_t distance=sequence-cumulative_ack_;
        // Retries at/below CACK remain legal. Only the forward serial interval
        // beyond CACK+MP_RANGE is closed, including when the sequence wraps.
        return distance>=0x80000000u || distance<=*advertised_range_;
    }
    uint32_t cumulative_ack() const { return cumulative_ack_; }
    std::optional<uint32_t> advertised_range() const { return advertised_range_; }
private:
    uint32_t cumulative_ack_,zero_override_;
    std::optional<uint32_t> advertised_range_,last_mpr_ack_;
};
} // namespace UET::PDS
