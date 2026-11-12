#pragma once
#include <algorithm>
#include <cstdint>

namespace UET::Runtime {
constexpr uint64_t kMaximumInitialRtoNs=8000000000ULL; // UE 1.1 §3.5.5 / §3.5.15.3.
constexpr uint64_t kMaximumBackoffNs=UINT64_MAX; // Representation limit, not an early protocol cap.

inline uint64_t retransmission_timeout_ns(uint64_t initial_ns,uint16_t timeout_retries) {
    if (!initial_ns) return 0; // A configured zero expires at the transmit event's timestamp.
    // Divide before shifting, so even a saturated retry counter cannot wrap
    // a nanosecond duration or invoke an undefined oversized shift.
    if (timeout_retries>=64 || initial_ns>(kMaximumBackoffNs>>timeout_retries)) return kMaximumBackoffNs;
    return std::min(kMaximumBackoffNs,initial_ns<<timeout_retries);
}
}
