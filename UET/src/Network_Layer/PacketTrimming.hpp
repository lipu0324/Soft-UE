#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>

namespace UET::NetworkLayer {
// Fabric-wide DSCP meanings, not standardized numeric codepoints. The defaults
// are this simulator's explicit mapping (§3.6.4.7 / §4.1), and may be replaced
// consistently at switches and FEPs. MIN_TRIM_SIZE counts IP payload bytes.
struct TrimmingOptions {
    uint8_t trimmable_dscp=0;
    uint8_t trimmed_dscp=8;
    std::optional<uint8_t> last_hop_dscp=16;
    uint8_t control_dscp=48;
    uint8_t no_trim_dscp=32; // Request TC without trimming, e.g. numbered ROD CPs.
    uint8_t trimmed_traffic_class=1;
    size_t minimum_ip_payload=24; // UDP(8)+largest current PDS request header(16).

    void validate() const {
        if (trimmable_dscp>63 || trimmed_dscp>63 || control_dscp>63 || no_trim_dscp>63 ||
            trimmed_traffic_class>7 || minimum_ip_payload<24 || minimum_ip_payload>65535 ||
            trimmable_dscp==trimmed_dscp || trimmable_dscp==control_dscp || trimmed_dscp==control_dscp ||
            no_trim_dscp==trimmable_dscp || no_trim_dscp==trimmed_dscp || no_trim_dscp==control_dscp ||
            (last_hop_dscp && (*last_hop_dscp>63 || *last_hop_dscp==trimmable_dscp ||
                *last_hop_dscp==trimmed_dscp || *last_hop_dscp==control_dscp || *last_hop_dscp==no_trim_dscp)))
            throw std::invalid_argument("invalid packet trimming configuration");
    }
    bool is_trimmed(uint8_t dscp) const { return dscp==trimmed_dscp || (last_hop_dscp && dscp==*last_hop_dscp); }
};
} // namespace UET::NetworkLayer
