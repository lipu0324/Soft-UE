#pragma once
#include "MemoryKey.hpp"
#include <cstdint>
#include <stdexcept>

namespace UET::SES {
// Simulator policy for provider-assigned RKEYs (§2.2.5.3.4.1). Share this
// sequence with the FEP Host when replacing a native Endpoint: restarting
// its counter could authorize an old key against unrelated new storage.
// Application-assigned keys retain their explicit registration semantics.
class MemoryKeyAllocator {
public:
    explicit MemoryKeyAllocator(uint64_t first_rkey=1):next_rkey_(first_rkey) {
        if (!first_rkey || first_rkey>MemoryKeyFormat::Rkey+1)
            throw std::invalid_argument("invalid provider RKEY sequence start");
    }
    uint64_t allocate() {
        if (next_rkey_>MemoryKeyFormat::Rkey) throw std::overflow_error("memory keys exhausted");
        return next_rkey_++; // The exhausted sentinel fits in 64 bits; never wrap 48 bits.
    }
private:
    uint64_t next_rkey_;
};
} // namespace UET::SES
