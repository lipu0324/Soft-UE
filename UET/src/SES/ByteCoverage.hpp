#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <map>

namespace UET::SES {
// §3.4.5.3 explicitly permits rendezvous READs to overlap eager data and
// previously read bytes. Track the UNION of confirmed original-message bytes;
// ordinary ReadCoverage intentionally rejects partial overlapping fragments.
class ByteCoverage {
public:
    bool cover(uint32_t offset,uint32_t length,uint32_t total) {
        if (offset>total || length>total-offset) return false;
        if (!length) return true; // A zero-byte marker is tracked separately.
        uint64_t begin=offset,end=uint64_t{offset}+length;
        auto next=intervals_.lower_bound(offset);
        if (next!=intervals_.begin()) {
            const auto previous=std::prev(next);
            if (uint64_t{previous->first}+previous->second>=begin) next=previous;
        }
        while (next!=intervals_.end() && next->first<=end) {
            begin=std::min<uint64_t>(begin,next->first);
            end=std::max<uint64_t>(end,uint64_t{next->first}+next->second);
            bytes_-=next->second; next=intervals_.erase(next);
        }
        const auto merged_length=static_cast<uint32_t>(end-begin);
        intervals_.emplace(static_cast<uint32_t>(begin),merged_length); bytes_+=merged_length;
        return true;
    }
    uint64_t bytes() const { return bytes_; }
    size_t intervals() const { return intervals_.size(); }
private:
    std::map<uint32_t,uint32_t> intervals_;
    uint64_t bytes_=0;
};
} // namespace UET::SES
