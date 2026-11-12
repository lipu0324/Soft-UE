#pragma once
#include <algorithm>
#include <cstdint>
#include <stdexcept>

namespace UET::Runtime {
constexpr uint64_t kMaximumInitialRtoNs=8000000000ULL; // UE 1.1 §3.5.5 / §3.5.15.3.
constexpr uint64_t kMaximumBackoffNs=UINT64_MAX; // Representation limit, not an early protocol cap.

constexpr uint8_t kInfiniteRetryLimit=15; // §3.5.5: maximum four-bit setting means unlimited retries.
constexpr uint8_t kDefaultRetryLimit=5;

inline bool retry_permitted(uint64_t retries,uint8_t configured_limit) {
    if (configured_limit>kInfiniteRetryLimit) throw std::invalid_argument("retry limit must be 0..15");
    return configured_limit==kInfiniteRetryLimit || retries<configured_limit;
}
inline uint64_t next_retry_count(uint64_t retries) {
    // Local counters are also NIC attempt identities. Wrapping one would
    // allow a stale departure callback to start a timer for a new attempt.
    if (retries==UINT64_MAX) throw std::overflow_error("retry attempt identity exhausted");
    return retries+1;
}
inline uint64_t retransmission_timeout_ns(uint64_t initial_ns,uint64_t timeout_retries) {
    if (!initial_ns) return 0; // A configured zero expires at the transmit event's timestamp.
    // Divide before shifting, so even a saturated retry counter cannot wrap
    // a nanosecond duration or invoke an undefined oversized shift.
    if (timeout_retries>=64 || initial_ns>(kMaximumBackoffNs>>timeout_retries)) return kMaximumBackoffNs;
    return std::min(kMaximumBackoffNs,initial_ns<<timeout_retries);
}
}
