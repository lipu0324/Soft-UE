#pragma once
#include "IntegerAtomics.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <optional>
#include <stdexcept>
#include <vector>

namespace UET::SES {

enum class MemoryError { InvalidKey, WrongJob, WrongEndpoint, Permission, Bounds, Alignment };
class MemoryAccessError : public std::runtime_error {
public:
    explicit MemoryAccessError(MemoryError code) : std::runtime_error("memory access rejected"), code(code) {}
    MemoryError code;
};
enum class Access : uint8_t { Read = 1, Write = 2, Atomic = 4 };
inline uint8_t operator|(Access a, Access b) { return static_cast<uint8_t>(a) | static_cast<uint8_t>(b); }

// Storage selection is local policy. Remote requests see only a registered key
// and a checked offset (§3.4.4); they never supply a process pointer.
class MemoryStorage {
public:
    virtual ~MemoryStorage()=default;
    virtual uint64_t size() const=0;
    virtual size_t allocated_pages() const=0;
    virtual void read(uint64_t offset,uint8_t* destination,size_t length) const=0;
    virtual void write(uint64_t offset,const uint8_t* source,size_t length)=0;
protected:
    void bounds(uint64_t offset,uint64_t length) const {
        if (offset>size() || length>size()-offset) throw MemoryAccessError(MemoryError::Bounds);
    }
};

// A logically large simulation region allocates only pages that are written.
class SparseMemory final : public MemoryStorage {
public:
    static constexpr size_t kPageSize = 4096;
    explicit SparseMemory(uint64_t size) : size_(size) {}
    uint64_t size() const override { return size_; }
    size_t allocated_pages() const override { return pages_.size(); }
    void read(uint64_t offset, uint8_t* destination, size_t length) const override {
        bounds(offset,length);
        if (length && !destination) throw std::invalid_argument("null destination");
        while (length) {
            const auto page = offset / kPageSize;
            const auto within = static_cast<size_t>(offset % kPageSize);
            const auto count = std::min(length, kPageSize - within);
            auto found = pages_.find(page);
            if (found == pages_.end()) std::memset(destination, 0, count);
            else std::memcpy(destination, found->second.data() + within, count);
            offset += count; destination += count; length -= count;
        }
    }
    void write(uint64_t offset, const uint8_t* source, size_t length) override {
        bounds(offset,length);
        if (length && !source) throw std::invalid_argument("null source");
        while (length) {
            const auto page = offset / kPageSize;
            const auto within = static_cast<size_t>(offset % kPageSize);
            const auto count = std::min(length, kPageSize - within);
            std::memcpy(pages_[page].data() + within, source, count);
            offset += count; source += count; length -= count;
        }
    }
private:
    uint64_t size_;
    std::map<uint64_t, std::array<uint8_t,kPageSize>> pages_;
};

// The real-time/provider adapter registers an application-owned buffer through
// this local-only constructor. Its optional owner keeps shared storage alive;
// otherwise the application must retain the buffer until MR deregistration.
class BufferMemory final : public MemoryStorage {
public:
    BufferMemory(uint8_t* buffer,size_t length,std::shared_ptr<void> owner={})
        : buffer_(buffer),length_(length),owner_(std::move(owner)) {
        if (length && !buffer) throw std::invalid_argument("null registered buffer");
    }
    uint64_t size() const override { return length_; }
    size_t allocated_pages() const override {
        return length_/SparseMemory::kPageSize+(length_%SparseMemory::kPageSize!=0);
    }
    void read(uint64_t offset,uint8_t* destination,size_t length) const override {
        bounds(offset,length);
        if (!length) return;
        if (!destination) throw std::invalid_argument("null destination");
        std::memmove(destination,buffer_+offset,length);
    }
    void write(uint64_t offset,const uint8_t* source,size_t length) override {
        bounds(offset,length);
        if (!length) return;
        if (!source) throw std::invalid_argument("null source");
        std::memmove(buffer_+offset,source,length);
    }
private:
    uint8_t* buffer_;
    size_t length_;
    std::shared_ptr<void> owner_;
};

struct Region {
    uint64_t key;
    uint32_t job;
    uint16_t pid; // 0 means domain scope, otherwise PIDonFEP scope.
    uint8_t permissions;
    bool idempotent_safe;
    std::shared_ptr<MemoryStorage> storage;
    bool allow_any_job=false;
    std::optional<uint16_t> resource_index; // No index means domain scope.
};

struct RegionOptions {
    bool idempotent_safe=false;
    bool allow_any_job=false; // §3.4.4.2: authorize any valid wire JobID.
    std::optional<uint16_t> resource_index;
};

enum class Atomic64 { Add, Swap, CompareSwap, And, Or, Xor, Min, Max };

class MemoryRegistry {
public:
    static constexpr uint64_t kIdempotentSafe = 1ULL << 63;
    static constexpr uint64_t kProviderSpace = 1ULL << 48;
    static constexpr uint64_t kRkeyMask = (1ULL << 48) - 1;

    void add_job(uint32_t job) {
        if (!job || job > 0xffffff) throw std::invalid_argument("invalid JobID");
        jobs_.insert(job);
    }
    void remove_job(uint32_t job) {
        jobs_.erase(job);
        for (auto it=regions_.begin(); it!=regions_.end(); )
            if (it->second.job == job) it = regions_.erase(it); else ++it;
    }
    bool has_job(uint32_t job) const { return jobs_.count(job) != 0; }
    Region register_region(uint32_t job, uint16_t pid, uint64_t length,
                           uint8_t permissions, bool idempotent_safe = false) {
        RegionOptions options; options.idempotent_safe=idempotent_safe;
        return register_region(job,pid,length,permissions,options);
    }
    Region register_region(uint32_t job,uint16_t pid,uint64_t length,
                           uint8_t permissions,const RegionOptions& options) {
        return register_storage(job,pid,std::make_shared<SparseMemory>(length),permissions,options);
    }
    Region register_buffer(uint32_t job,uint16_t pid,uint8_t* buffer,size_t length,
                           uint8_t permissions,const RegionOptions& options={},std::shared_ptr<void> owner={}) {
        return register_storage(job,pid,std::make_shared<BufferMemory>(buffer,length,std::move(owner)),permissions,options);
    }
    Region register_storage(uint32_t job,uint16_t pid,std::shared_ptr<MemoryStorage> storage,
                            uint8_t permissions,const RegionOptions& options={}) {
        if (!has_job(job)) throw MemoryAccessError(MemoryError::WrongJob);
        if (!storage || pid > 0xfff || (options.resource_index && *options.resource_index>0xfff) || (permissions & ~uint8_t{7}))
            throw std::invalid_argument("invalid region attributes");
        if (next_key_ > kRkeyMask) throw std::overflow_error("memory keys exhausted");
        const auto key = kProviderSpace | next_key_++ | (options.idempotent_safe ? kIdempotentSafe : 0);
        Region region{key,job,pid,permissions,options.idempotent_safe,std::move(storage)};
        region.allow_any_job=options.allow_any_job; region.resource_index=options.resource_index;
        regions_.emplace(key,region);
        return region;
    }
    bool deregister(uint64_t key) { return regions_.erase(key) != 0; }
    const Region& authorize(uint32_t job, uint16_t pid, uint64_t key,
                            uint64_t offset, uint64_t length, Access access,std::optional<uint16_t> resource_index={}) const {
        const auto found = regions_.find(key);
        if (found == regions_.end()) throw MemoryAccessError(MemoryError::InvalidKey);
        const auto& region = found->second;
        if (job>0xffffff || (!region.allow_any_job && (!has_job(job) || region.job != job)))
            throw MemoryAccessError(MemoryError::WrongJob);
        if (region.pid && region.pid != pid) throw MemoryAccessError(MemoryError::WrongEndpoint);
        if (resource_index && region.resource_index && region.resource_index!=resource_index)
            throw MemoryAccessError(MemoryError::InvalidKey);
        if (!(region.permissions & static_cast<uint8_t>(access))) throw MemoryAccessError(MemoryError::Permission);
        if (offset > region.storage->size() || length > region.storage->size() - offset)
            throw MemoryAccessError(MemoryError::Bounds);
        return region;
    }
    void write(uint32_t job, uint16_t pid, uint64_t key, uint64_t offset,
               const std::vector<uint8_t>& bytes,std::optional<uint16_t> resource_index={}) {
        const auto& region = authorize(job,pid,key,offset,bytes.size(),Access::Write,resource_index);
        region.storage->write(offset,bytes.data(),bytes.size());
    }
    std::vector<uint8_t> read(uint32_t job, uint16_t pid, uint64_t key,
                             uint64_t offset, size_t length) const {
        const auto& region = authorize(job,pid,key,offset,length,Access::Read);
        std::vector<uint8_t> bytes(length);
        region.storage->read(offset,bytes.data(),length);
        return bytes;
    }
    // An atomic event is indivisible in the single-threaded protocol runtime.
    // The initial primitive is unsigned 64-bit, explicitly little endian.
    uint64_t atomic(uint32_t job, uint16_t pid, uint64_t key, uint64_t offset,
                    Atomic64 operation, uint64_t operand, uint64_t compare = 0) {
        const auto& region = authorize(job,pid,key,offset,8,Access::Atomic);
        if (offset % 8) throw MemoryAccessError(MemoryError::Alignment);
        std::array<uint8_t,8> bytes{};
        region.storage->read(offset,bytes.data(),bytes.size());
        uint64_t previous = 0;
        for (size_t i=0; i<8; ++i) previous |= uint64_t{bytes[i]} << (8*i);
        uint64_t next;
        switch (operation) {
        case Atomic64::Add: next = previous + operand; break;
        case Atomic64::Swap: next = operand; break;
        case Atomic64::CompareSwap: next = previous == compare ? operand : previous; break;
        case Atomic64::And: next = previous & operand; break;
        case Atomic64::Or: next = previous | operand; break;
        case Atomic64::Xor: next = previous ^ operand; break;
        case Atomic64::Min: next = std::min(previous,operand); break;
        case Atomic64::Max: next = std::max(previous,operand); break;
        default: throw std::invalid_argument("unsupported atomic");
        }
        for (size_t i=0; i<8; ++i) bytes[i] = static_cast<uint8_t>(next >> (8*i));
        region.storage->write(offset,bytes.data(),bytes.size());
        return previous;
    }
    void atomic_elements(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,
                         IntegerAtomicOperation operation,IntegerAtomicDatatype datatype,
                         const std::vector<uint8_t>& operands,std::optional<uint16_t> resource_index={}) {
        const auto element_width=integer_atomic_width(datatype);
        if (offset%element_width) throw MemoryAccessError(MemoryError::Alignment);
        if (operands.size()%element_width) throw std::invalid_argument("incomplete atomic element");
        const auto& region=authorize(job,pid,key,offset,operands.size(),Access::Atomic,resource_index);
        // §3.4.7.3: atomics need both read and write permission in addition
        // to the explicit atomic capability of this simulator's MR model.
        if ((region.permissions&3u)!=3u) throw MemoryAccessError(MemoryError::Permission);
        for (size_t position=0;position<operands.size();position+=element_width) {
            std::array<uint8_t,8> target_bytes{};
            region.storage->read(offset+position,target_bytes.data(),element_width);
            uint64_t target_value=0,operand_value=0;
            for (size_t byte=0;byte<element_width;++byte) {
                target_value|=uint64_t{target_bytes[byte]}<<(8*byte);
                operand_value|=uint64_t{operands[position+byte]}<<(8*byte);
            }
            const auto result=integer_atomic_result(target_value,operand_value,operation,datatype);
            for (size_t byte=0;byte<element_width;++byte) target_bytes[byte]=result>>(8*byte);
            region.storage->write(offset+position,target_bytes.data(),element_width);
        }
    }
private:
    uint64_t next_key_ = 1;
    std::set<uint32_t> jobs_;
    std::map<uint64_t,Region> regions_;
};
} // namespace UET::SES
