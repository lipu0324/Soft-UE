#pragma once
#include <cstdint>
#include <stdexcept>

namespace UET::SES {
enum class KeyAssignment { Application, Provider };

// UE 1.1 Table 2-13. The full 64-bit value crosses the API/wire boundary;
// mr_key_size describes the RKEY (remote memory-region key) portion, at most
// six bytes. Merely
// having a well-formed key never authorizes access to a registered buffer.
struct MemoryKeyFormat {
    static constexpr uint64_t IdempotentSafe=uint64_t{1}<<63;
    static constexpr uint64_t Optimized=uint64_t{1}<<62;
    static constexpr uint64_t Reserved=uint64_t{0x3f}<<56;
    static constexpr uint64_t Vendor=uint64_t{0xff}<<48;
    static constexpr uint64_t Rkey=(uint64_t{1}<<48)-1;
    static void validate(uint64_t key,KeyAssignment assignment,unsigned rkey_bytes=6) {
        if (!rkey_bytes || rkey_bytes>6) throw std::invalid_argument("RKEY width must be 1..6 bytes");
        if (key&Reserved) throw std::invalid_argument("reserved memory-key bits must be zero");
        if (assignment==KeyAssignment::Application && (key&Vendor))
            throw std::invalid_argument("application memory key cannot set vendor bits");
        const uint64_t supported_rkey=(uint64_t{1}<<(rkey_bytes*8))-1;
        if ((key&Rkey)>supported_rkey) throw std::invalid_argument("RKEY exceeds advertised width");
        if ((key&Optimized) && (key&Rkey)>0xfff)
            throw std::invalid_argument("optimized memory key requires a 12-bit index");
    }
};
} // namespace UET::SES
