#pragma once
#include <cstdint>
#include <optional>

namespace UET::PDS {
// UE 1.1 §3.5.21.1 items 8–13. An ACK ends the current GoBackN episode.
// Feedback from higher packets following the same gap is not a new loss.
// The first RETX=1 NACK permits one more recovery; further equal-gap RETX
// NACKs wait for RTO instead of creating an unbounded retransmission storm.
class OrderedRecovery {
public:
    bool active() const { return expected_.has_value(); }
    void acknowledged() { expected_.reset(); retransmitted_nack_seen_=false; }
    bool observe(uint32_t expected,bool retransmitted) {
        if (!expected_) {
            expected_=expected; retransmitted_nack_seen_=retransmitted; return true;
        }
        if (retransmitted && !retransmitted_nack_seen_) {
            retransmitted_nack_seen_=true; expected_=expected; return true;
        }
        const uint32_t advance=expected-*expected_;
        if (advance && advance<0x80000000u) { expected_=expected; return true; }
        return false;
    }
private:
    std::optional<uint32_t> expected_;
    bool retransmitted_nack_seen_=false;
};
}
