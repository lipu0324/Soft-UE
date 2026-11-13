#pragma once
#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>

namespace UET::PDS {
// Table 3-35 / §3.5.11.13: Default_MPR is an encoding, not a packet count.
// A software transmit-cache limit is a separate implementation resource.
struct PsnRangeConfiguration {
    uint32_t default_mpr=8;
    uint32_t local_packet_capacity=8;
    // A fixed receive advertisement; omitted means the normalized Default_MPR.
    // Zero is useful for small research fabrics with a common nonzero override.
    std::optional<uint32_t> advertised_mpr;

    void validate(uint32_t zero_override) const {
        if (default_mpr>255 || !local_packet_capacity || local_packet_capacity>32640 ||
            (advertised_mpr && *advertised_mpr>255) || zero_override>32640)
            throw std::invalid_argument("invalid PDS PSN range configuration");
        if (advertised_mpr && !*advertised_mpr && !zero_override)
            throw std::invalid_argument("bounded zero-MPR receive policy requires a nonzero fabric override");
    }
    uint8_t initial_encoding() const { return static_cast<uint8_t>(std::max(1u,default_mpr)); }
    uint32_t initial_range() const { return uint32_t{initial_encoding()}*128; }
    uint8_t receive_encoding() const { return static_cast<uint8_t>(advertised_mpr.value_or(initial_encoding())); }
    uint32_t receive_range(uint32_t zero_override) const {
        return receive_encoding()?uint32_t{receive_encoding()}*128:zero_override;
    }
};
} // namespace UET::PDS
