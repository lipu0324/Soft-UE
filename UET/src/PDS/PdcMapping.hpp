#pragma once
#include <cstdint>
#include <initializer_list>
#include <tuple>

namespace UET::PDS {
// §3.5.8.1 requires the base FA/TC/mode tuple and any combination of these
// four process/resource fields. Each delivery mode has an independent policy.
struct PdcMappingFields {
    bool include_job_id=true;
    bool include_source_pid=false;
    bool include_target_pid=false;
    bool include_resource_index=false;
};
struct PdcMappingConfiguration {
    PdcMappingFields rud,rod;
    const PdcMappingFields& fields(bool ordered) const { return ordered?rod:rud; }
};
struct PdcMappingIdentity {
    uint16_t source_pid=1;
    uint16_t target_pid=1;
    uint16_t resource_index=1;
    bool valid() const { return source_pid<=0xfff && target_pid<=0xfff && resource_index<=0xfff; }
};
struct InitiatorPdcKey {
    uint32_t source_fa,destination_fa;
    uint8_t traffic_class,delivery_mode;
    uint32_t job_id;
    uint16_t source_pid,target_pid,resource_index;
    auto identity() const {
        return std::tie(source_fa,destination_fa,traffic_class,delivery_mode,
            job_id,source_pid,target_pid,resource_index);
    }
    bool operator<(const InitiatorPdcKey& other) const { return identity()<other.identity(); }
    // The hash chooses only a starting ID. Full key comparison and probing
    // preserve isolation when hashes collide; this is a simulator allocation
    // policy, not a standardized mapping from fields to numeric PDCIDs.
    uint64_t allocation_hash() const {
        uint64_t result=14695981039346656037ULL;
        for (uint32_t field:{source_fa,destination_fa,uint32_t{traffic_class},uint32_t{delivery_mode},
                            job_id,uint32_t{source_pid},uint32_t{target_pid},uint32_t{resource_index}})
            for (unsigned shift=0;shift<32;shift+=8) {
                result^=(field>>shift)&255; result*=1099511628211ULL;
            }
        return result;
    }
};
} // namespace UET::PDS
