#pragma once
#include <cstddef>
#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

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
    uint8_t data_traffic_class=0; // Local queue selected for this policy's DATA and NO_TRIM DSCPs.

    void validate() const {
        if (trimmable_dscp>63 || trimmed_dscp>63 || control_dscp>63 || no_trim_dscp>63 ||
            trimmed_traffic_class>7 || data_traffic_class>7 || minimum_ip_payload<24 || minimum_ip_payload>65535 ||
            trimmable_dscp==trimmed_dscp || trimmable_dscp==control_dscp || trimmed_dscp==control_dscp ||
            no_trim_dscp==trimmable_dscp || no_trim_dscp==trimmed_dscp || no_trim_dscp==control_dscp ||
            (last_hop_dscp && (*last_hop_dscp>63 || *last_hop_dscp==trimmable_dscp ||
                *last_hop_dscp==trimmed_dscp || *last_hop_dscp==control_dscp || *last_hop_dscp==no_trim_dscp)))
            throw std::invalid_argument("invalid packet trimming configuration");
    }
    bool is_trimmed(uint8_t dscp) const { return dscp==trimmed_dscp || (last_hop_dscp && dscp==*last_hop_dscp); }
};

// Simulator configuration policy: DATA/NO_TRIM/TRIMMED/LASTHOP codepoints
// identify one configured data class unambiguously. All classes share one
// control DSCP. These are configured meanings, not standard numeric values.
inline void validate_trimming_policy_set(const std::vector<TrimmingOptions>& policies) {
    std::array<bool,8> classes{};
    std::array<bool,64> noncontrol_dscps{};
    std::optional<uint8_t> control;
    for (const auto& policy:policies) {
        policy.validate();
        if (classes[policy.data_traffic_class]) throw std::invalid_argument("duplicate trimming data traffic class");
        classes[policy.data_traffic_class]=true;
        if (control && *control!=policy.control_dscp) throw std::invalid_argument("trimming classes require a common control DSCP");
        control=policy.control_dscp;
        const auto reserve=[&](uint8_t dscp) {
            if (noncontrol_dscps[dscp] || dscp==*control)
                throw std::invalid_argument("ambiguous trimming DSCP assignment");
            noncontrol_dscps[dscp]=true;
        };
        reserve(policy.trimmable_dscp);
        reserve(policy.no_trim_dscp);
        reserve(policy.trimmed_dscp);
        if (policy.last_hop_dscp) reserve(*policy.last_hop_dscp);
        if (noncontrol_dscps[*control]) throw std::invalid_argument("control DSCP overlaps data/trimmed traffic");
    }
}

inline void validate_data_traffic_class_dscps(const std::array<std::optional<uint8_t>,8>& data_dscps,
                                            const std::vector<TrimmingOptions>& policies) {
    validate_trimming_policy_set(policies);
    const uint8_t control=policies.empty()?48:policies.front().control_dscp;
    std::array<bool,64> assigned{};
    for (size_t traffic_class=0;traffic_class<data_dscps.size();++traffic_class) {
        if (!data_dscps[traffic_class]) continue;
        const auto dscp=*data_dscps[traffic_class];
        if (dscp>=64 || dscp==control || assigned[dscp]) throw std::invalid_argument("ambiguous data TC DSCP assignment");
        assigned[dscp]=true;
        for (const auto& policy:policies) {
            if (policy.data_traffic_class==traffic_class && dscp!=policy.trimmable_dscp)
                throw std::invalid_argument("data TC DSCP differs from its trimming policy");
            if ((policy.data_traffic_class!=traffic_class && dscp==policy.trimmable_dscp) ||
                dscp==policy.no_trim_dscp || dscp==policy.trimmed_dscp ||
                (policy.last_hop_dscp && dscp==*policy.last_hop_dscp))
                throw std::invalid_argument("data TC DSCP overlaps a different packet role");
        }
    }
}
} // namespace UET::NetworkLayer
