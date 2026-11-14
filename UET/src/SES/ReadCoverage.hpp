#pragma once
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>
#include <tuple>
#include "../Transport_Layer.hpp"

namespace UET::SES {
// A READ packet credit belongs to one direction of one PDC incarnation. JobID
// and message ID alone cannot identify a delayed packet after context reuse.
struct ReadPacketIdentity {
    uint32_t peer;
    uint16_t local_pdc;
    uint32_t connection_start_psn,sequence;
    static ReadPacketIdentity from(const PDC_SES_req& request) {
        return {request.source_fep,request.PDCID,request.connection_start_psn,request.orig_psn};
    }
    bool operator<(const ReadPacketIdentity& other) const {
        return std::tie(peer,local_pdc,connection_start_psn,sequence)<
            std::tie(other.peer,other.local_pdc,other.connection_start_psn,other.sequence);
    }
};

// Coalesced coverage keeps ordered gigabyte READs at one interval. Out-of-order
// state is bounded by the real PDS receive window, rather than by message size.
class ReadCoverage {
public:
    enum class Addition { Added, Duplicate, Invalid };
    Addition add(uint32_t offset,uint32_t length,uint32_t total) {
        if (offset>total || length>total-offset) return Addition::Invalid;
        auto next=intervals_.upper_bound(offset);
        if (next!=intervals_.begin()) {
            const auto previous=std::prev(next);
            const uint64_t previous_end=uint64_t{previous->first}+previous->second;
            if (previous->first<=offset && previous_end>=uint64_t{offset}+length) return Addition::Duplicate;
            if (previous_end>offset) return Addition::Invalid;
        }
        if (next!=intervals_.end() && uint64_t{offset}+length>next->first) return Addition::Invalid;
        uint32_t merged_offset=offset,merged_length=length;
        if (next!=intervals_.begin()) {
            const auto previous=std::prev(next);
            if (uint64_t{previous->first}+previous->second==offset) {
                merged_offset=previous->first; merged_length+=previous->second; intervals_.erase(previous);
            }
        }
        if (next!=intervals_.end() && uint64_t{offset}+length==next->first) {
            merged_length+=next->second; intervals_.erase(next);
        }
        intervals_.emplace(merged_offset,merged_length); bytes_+=length;
        return Addition::Added;
    }
    uint64_t bytes() const { return bytes_; }
    size_t intervals() const { return intervals_.size(); }
private:
    uint64_t bytes_=0;
    std::map<uint32_t,uint32_t> intervals_;
};
} // namespace UET::SES
