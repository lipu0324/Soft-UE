#pragma once
#include <cstdint>
#include <map>
#include <stdexcept>

namespace UET::PDS {
// UE 1.1 §3.5.8.2, plaintext start selection. This is a reproducible PRNG,
// not the authenticated Start_PSN negotiation required by TSS (§3.5.8.2.1).
class InitialSequenceAllocator {
public:
    explicit InitialSequenceAllocator(uint64_t seed):random_state_(seed) {}
    void reseed(uint64_t seed) { random_state_=seed; } // Retain the previous epochs across reconfiguration.
    uint32_t reserve(uint16_t local_pdc) {
        if (!local_pdc) throw std::invalid_argument("PDC identifier zero is reserved");
        const uint32_t random_bits=next_random_word();
        const auto previous=last_used_.find(local_pdc);
        uint32_t start=random_bits;
        if (previous!=last_used_.end()) {
            // Keep at least 2^16 separation and less than half the serial
            // number space. Unsigned addition intentionally handles wrap.
            constexpr uint32_t minimum_separation=uint32_t{1}<<16;
            constexpr uint32_t separation_choices=(uint32_t{1}<<31)-minimum_separation;
            start=previous->second+minimum_separation+random_bits%separation_choices;
        }
        // Even a failed creation consumes an epoch. A later attempt cannot
        // silently reuse an initial sequence already reserved by the manager.
        last_used_[local_pdc]=start-1;
        return start;
    }
    void observe_last(uint16_t local_pdc,uint32_t last_allocated_psn) {
        const auto previous=last_used_.find(local_pdc);
        if (previous==last_used_.end()) throw std::logic_error("retiring an unreserved PDC identifier");
        previous->second=last_allocated_psn;
    }
private:
    uint64_t random_state_;
    std::map<uint16_t,uint32_t> last_used_; // One retained value per local PDC ID, independent of peer.
    uint32_t next_random_word() {
        // SplitMix64: fixed unsigned arithmetic is reproducible across hosts.
        // The injected seed, not wall-clock time, selects the simulation run.
        uint64_t mixed=(random_state_+=UINT64_C(0x9e3779b97f4a7c15));
        mixed=(mixed^(mixed>>30))*UINT64_C(0xbf58476d1ce4e5b9);
        mixed=(mixed^(mixed>>27))*UINT64_C(0x94d049bb133111eb);
        return static_cast<uint32_t>((mixed^(mixed>>31))>>32);
    }
};
}
