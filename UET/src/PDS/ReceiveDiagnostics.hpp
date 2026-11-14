#pragma once
#include <cstdint>
#include <limits>

namespace UET::PDS {
// UE 1.1 Table 3-36 and §3.5.11.1/.3. These are host-local management
// counters, independent of any PDC: an unknown type cannot identify a safe
// context to update. The simulator selects 16-bit saturation at overflow;
// explicit management clear starts a new observation interval.
struct ReceiveErrorCounters {
    uint16_t pds_type_invalid=0;
    uint16_t pds_ctl_type_invalid=0;

    void record_invalid_type() { increment(pds_type_invalid); }
    void record_invalid_control_type() { increment(pds_ctl_type_invalid); }
private:
    static void increment(uint16_t& counter) {
        if (counter!=std::numeric_limits<uint16_t>::max()) ++counter;
    }
};
} // namespace UET::PDS
