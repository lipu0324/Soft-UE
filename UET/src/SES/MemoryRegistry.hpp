#pragma once
#include "IntegerAtomics.hpp"
#include "FetchingAtomics.hpp"
#include "MemoryKey.hpp"
#include "MemoryKeyAllocator.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <list>
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
enum class MemoryAccessOrigin { RemoteRequest, LocalPlacement, RendezvousSource };
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
            auto found=pages_.find(page);
            // An absent page already represents zero. Large zero-filled
            // transfers must not materialize gigabytes of identical pages.
            if (found!=pages_.end() || !std::all_of(source,source+count,[](uint8_t byte) { return byte==0; })) {
                if (found==pages_.end()) found=pages_.emplace(page,std::array<uint8_t,kPageSize>{}).first;
                std::memcpy(found->second.data()+within,source,count);
            }
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
    uint16_t pid; // Local requested PID; pid_scope distinguishes real PID zero from domain scope.
    uint8_t permissions;
    bool idempotent_safe;
    std::shared_ptr<MemoryStorage> storage;
    bool allow_any_job=false;
    std::optional<uint16_t> resource_index; // No index means domain scope.
    uint64_t registration_id=0; // Local revocation identity, never a wire field.
    std::weak_ptr<const int> registry_authority;
    std::optional<uint16_t> pid_scope;
    bool local_placement_only=false; // Trusted postings/results may use this region; a wire key cannot grant RMA access.
    bool rendezvous_source_only=false; // Only a trusted transaction may create a peer-bound read-only view.
};

struct RegionOptions {
    bool idempotent_safe=false;
    bool allow_any_job=false; // §3.4.4.2: authorize any valid wire JobID.
    std::optional<uint16_t> resource_index;
    std::optional<uint64_t> requested_key; // Native application-assigned, non-optimized key.
    bool bind_zero_pid=false; // Auto keys preserve the legacy domain-scope default for pid=0.
    bool local_placement_only=false;
    bool rendezvous_source_only=false;
};

enum class Atomic64 { Add, Swap, CompareSwap, And, Or, Xor, Min, Max };

class MemoryRegistry {
public:
    explicit MemoryRegistry(std::shared_ptr<MemoryKeyAllocator> provider_keys={})
        : key_allocator_(provider_keys?std::move(provider_keys):std::make_shared<MemoryKeyAllocator>()) {}
    MemoryRegistry(const MemoryRegistry&)=delete;
    MemoryRegistry& operator=(const MemoryRegistry&)=delete;
    static constexpr uint64_t kIdempotentSafe = MemoryKeyFormat::IdempotentSafe;
    static constexpr uint64_t kProviderSpace = 1ULL << 48;
    static constexpr uint64_t kRkeyMask = MemoryKeyFormat::Rkey;

    void add_job(uint32_t job) {
        if (job > 0xffffff) throw std::invalid_argument("invalid JobID");
        jobs_.insert(job);
    }
    void remove_job(uint32_t job) {
        jobs_.erase(job);
        for (auto bucket=regions_.begin();bucket!=regions_.end();) {
            auto& entries=bucket->second;
            entries.remove_if([job](const Region& region) { return region.job==job; });
            if (entries.empty()) bucket=regions_.erase(bucket); else ++bucket;
        }
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
        if (!storage || pid > 0xfff || (options.resource_index && *options.resource_index>0xfff) || (permissions & ~uint8_t{7}) ||
            (options.local_placement_only && options.rendezvous_source_only))
            throw std::invalid_argument("invalid region attributes");
        if (next_registration_==UINT64_MAX) throw std::overflow_error("registration identities exhausted");
        uint64_t key;
        auto resource_index=options.resource_index;
        if (options.requested_key) {
            key=*options.requested_key | (options.idempotent_safe?kIdempotentSafe:0);
            MemoryKeyFormat::validate(key,KeyAssignment::Application);
            if (key&MemoryKeyFormat::Optimized) {
                const auto index=static_cast<uint16_t>(key&0xfff);
                if (resource_index && *resource_index!=index) throw std::invalid_argument("optimized key and resource index differ");
                resource_index=index; // Table2-14: this field is the MR index for optimized RMA.
            } else if (!resource_index) resource_index=1; // Default native RMA resource, not a wildcard.
        } else {
            key=kProviderSpace | key_allocator_->allocate() | (options.idempotent_safe?kIdempotentSafe:0);
        }
        Region region{key,job,pid,permissions,bool(key&kIdempotentSafe),std::move(storage)};
        region.allow_any_job=options.allow_any_job; region.resource_index=resource_index;
        region.registration_id=++next_registration_;
        region.registry_authority=authority_;
        region.local_placement_only=options.local_placement_only;
        region.rendezvous_source_only=options.rendezvous_source_only;
        if (pid || options.bind_zero_pid || options.requested_key) region.pid_scope=pid;
        // §2.2.5.3.4.1: non-optimized key namespaces include Job/PID/RI.
        // Equal numeric application keys may identify independent regions in
        // different namespaces. IDEMPOTENT_SAFE describes the region; it does
        // not enlarge the 48-bit application RKEY namespace.
        const auto duplicate_scope=[&](uint64_t candidate_key) {
            const auto bucket=regions_.find(candidate_key);
            if (bucket==regions_.end()) return false;
            return std::any_of(bucket->second.begin(),bucket->second.end(),[&](const Region& existing) {
                return existing.pid_scope==region.pid_scope && existing.resource_index==resource_index &&
                    existing.allow_any_job==options.allow_any_job && (existing.allow_any_job || existing.job==job);
            });
        };
        if (duplicate_scope(key) || (options.requested_key && duplicate_scope(key^kIdempotentSafe)))
            throw std::invalid_argument("memory key already registered in this scope");
        auto& entries=regions_[key];
        try { entries.push_back(region); }
        catch (...) { if (entries.empty()) regions_.erase(key); throw; }
        return region;
    }
    bool deregister(uint64_t key) {
        const auto found=regions_.find(key);
        if (found==regions_.end()) return false;
        if (found->second.size()!=1) throw std::invalid_argument("ambiguous memory key; revoke its registration handle");
        regions_.erase(found); return true;
    }
    bool deregister(const Region& registration) {
        if (registration.registry_authority.lock()!=authority_) return false;
        const auto found=regions_.find(registration.key);
        if (found==regions_.end()) return false;
        auto& entries=found->second;
        const auto entry=std::find_if(entries.begin(),entries.end(),[&](const Region& region) {
            return region.registration_id==registration.registration_id;
        });
        if (entry==entries.end()) return false;
        entries.erase(entry); if (entries.empty()) regions_.erase(found); return true;
    }
    // Table2-47: optimized indices are scoped by Job/PID, or PID alone for
    // absolute lookup. SMALL omits the key's idempotent metadata. Resolving a
    // numeric key here grants no rights: the caller still uses ordinary MR
    // authorization for direction, private origins and the requested span.
    uint64_t resolve_optimized_key(uint32_t job,uint16_t pid,uint16_t index,bool relative=true) const {
        if (index>0xfff) throw MemoryAccessError(MemoryError::InvalidKey);
        const Region* selected=nullptr;
        bool job_found=false,pid_found=false,ambiguous=false;
        unsigned specificity=0;
        for (bool idempotent:{false,true}) {
            const auto key=MemoryKeyFormat::Optimized|index|(idempotent?kIdempotentSafe:0);
            const auto bucket=regions_.find(key); if (bucket==regions_.end()) continue;
            for (const auto& region:bucket->second) {
                if (relative && (job>0xffffff || (!region.allow_any_job && (!has_job(job) || region.job!=job)))) continue;
                job_found=true;
                if (region.pid_scope && *region.pid_scope!=pid) continue;
                pid_found=true;
                const unsigned score=(relative && !region.allow_any_job?4u:0u)+(region.pid_scope?2u:0u);
                if (!selected || score>specificity) { selected=&region; specificity=score; ambiguous=false; }
                else if (score==specificity) ambiguous=true;
            }
        }
        if (!job_found) {
            const auto base=MemoryKeyFormat::Optimized|index;
            if (!regions_.count(base) && !regions_.count(base|kIdempotentSafe)) throw MemoryAccessError(MemoryError::InvalidKey);
            throw MemoryAccessError(MemoryError::WrongJob);
        }
        if (!pid_found) throw MemoryAccessError(MemoryError::WrongEndpoint);
        if (!selected || ambiguous) throw MemoryAccessError(MemoryError::InvalidKey);
        return selected->key;
    }
    const Region& authorize(uint32_t job,uint16_t pid,uint64_t key,
                            uint64_t offset,uint64_t length,Access access,std::optional<uint16_t> resource_index={},
                            bool relative_addressing=true,MemoryAccessOrigin origin=MemoryAccessOrigin::RemoteRequest) const {
        if (!regions_.count(key) && (relative_addressing || !regions_.count(key^kIdempotentSafe)))
            throw MemoryAccessError(MemoryError::InvalidKey);
        const Region* selected=nullptr;
        bool job_found=false,pid_found=false,ambiguous=false;
        unsigned specificity=0;
        const size_t metadata_variants=relative_addressing?1:2;
        for (size_t variant=0;variant<metadata_variants;++variant) {
            const auto bucket=regions_.find(key^(variant?kIdempotentSafe:0));
            if (bucket==regions_.end()) continue;
            for (const auto& region:bucket->second) {
                if (relative_addressing && (job>0xffffff || (!region.allow_any_job && (!has_job(job) || region.job!=job)))) continue;
                job_found=true;
                if (region.pid_scope && *region.pid_scope!=pid) continue;
                pid_found=true;
                if (resource_index && region.resource_index && resource_index!=region.resource_index) continue;
                const unsigned score=(relative_addressing && !region.allow_any_job?4u:0u)+(region.pid_scope?2u:0u)+(resource_index && region.resource_index?1u:0u);
                if (!selected || score>specificity) { selected=&region; specificity=score; ambiguous=false; }
                else if (score==specificity) ambiguous=true;
            }
        }
        if (!job_found) throw MemoryAccessError(MemoryError::WrongJob);
        if (!pid_found) throw MemoryAccessError(MemoryError::WrongEndpoint);
        if (!selected || ambiguous || selected->key!=key) throw MemoryAccessError(MemoryError::InvalidKey);
        // Table 2-17: absolute addressing does not use JobID to select a
        // buffer. Ambiguous equal keys are rejected before Job authorization.
        return check_access(*selected,job,pid,offset,length,access,resource_index,origin);
    }
    const Region& authorize_local(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,uint64_t length,
                                 Access access,std::optional<uint16_t> resource_index={}) const {
        // This entry is reached from a trusted local posting/operation, never
        // from fields of an incoming RMA packet. Namespace, rights, bounds and
        // later exact-registration revocation checks still apply.
        return authorize(job,pid,key,offset,length,access,resource_index,true,MemoryAccessOrigin::LocalPlacement);
    }
    const Region& authorize_registration(const Region& registration,uint32_t job,uint16_t pid,
                            uint64_t offset,uint64_t length,Access access,std::optional<uint16_t> resource_index={},
                            MemoryAccessOrigin origin=MemoryAccessOrigin::LocalPlacement) const {
        if (registration.registry_authority.lock()!=authority_) throw MemoryAccessError(MemoryError::InvalidKey);
        const auto bucket=regions_.find(registration.key);
        if (bucket==regions_.end()) throw MemoryAccessError(MemoryError::InvalidKey);
        const auto found=std::find_if(bucket->second.begin(),bucket->second.end(),[&](const Region& region) {
            return region.registration_id==registration.registration_id;
        });
        if (found==bucket->second.end()) throw MemoryAccessError(MemoryError::InvalidKey);
        // A receive posting already selected a buffer. Authenticate that exact
        // live registration; never reselect by a peer's JobID or a reused key.
        return check_access(*found,job,pid,offset,length,access,resource_index,origin);
    }
    void write(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,
               const std::vector<uint8_t>& bytes,std::optional<uint16_t> resource_index={},bool relative_addressing=true) {
        const auto& region=authorize(job,pid,key,offset,bytes.size(),Access::Write,resource_index,relative_addressing);
        // §3.4.2.12: a zero-byte write authorizes the address but writes no
        // memory. Storage adapters may observe calls, so do not call write(0).
        if (!bytes.empty()) region.storage->write(offset,bytes.data(),bytes.size());
    }
    void write_registration(const Region& registration,uint32_t job,uint16_t pid,uint64_t offset,
               const std::vector<uint8_t>& bytes,std::optional<uint16_t> resource_index={}) {
        const auto& region=authorize_registration(registration,job,pid,offset,bytes.size(),Access::Write,resource_index);
        // §3.4.2.12: a zero-byte write authorizes the address but writes no
        // memory. Storage adapters may observe calls, so do not call write(0).
        if (!bytes.empty()) region.storage->write(offset,bytes.data(),bytes.size());
    }
    std::vector<uint8_t> read(uint32_t job,uint16_t pid,uint64_t key,
                             uint64_t offset,size_t length,std::optional<uint16_t> resource_index={},bool relative_addressing=true) const {
        const auto& region=authorize(job,pid,key,offset,length,Access::Read,resource_index,relative_addressing);
        std::vector<uint8_t> bytes(length);
        region.storage->read(offset,bytes.data(),length);
        return bytes;
    }
    // An atomic event is indivisible in the single-threaded protocol runtime.
    // The initial primitive is unsigned 64-bit, explicitly little endian.
    uint64_t atomic(uint32_t job, uint16_t pid, uint64_t key, uint64_t offset,
                    Atomic64 operation,uint64_t operand,uint64_t compare=0,std::optional<uint16_t> resource_index={},bool relative_addressing=true) {
        const auto& region = authorize(job,pid,key,offset,8,Access::Atomic,resource_index,relative_addressing);
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
        // §3.4.2.12: a zero-byte write authorizes the address but writes no
        // memory. Storage adapters may observe calls, so do not call write(0).
        if (!bytes.empty()) region.storage->write(offset,bytes.data(),bytes.size());
        return previous;
    }
    std::vector<uint8_t> fetch_atomic_element(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,
                         IntegerAtomicOperation operation,IntegerAtomicDatatype datatype,
                         const std::vector<uint8_t>& operand,const std::vector<uint8_t>& compare_or_mask={},
                         std::optional<uint16_t> resource_index={},bool relative_addressing=true,bool zero_length=false) {
        const auto width=integer_atomic_width(datatype);
        if (offset%width) throw MemoryAccessError(MemoryError::Alignment);
        if (zero_length && (operation!=IntegerAtomicOperation::Read && operation!=IntegerAtomicOperation::Write))
            throw std::invalid_argument("zero-byte atomic is put/get only");
        if (zero_length && (!operand.empty() || !compare_or_mask.empty())) throw std::invalid_argument("zero-byte atomic has operands");
        const auto& region=authorize(job,pid,key,offset,zero_length?0:width,Access::Atomic,resource_index,relative_addressing);
        if ((region.permissions&3u)!=3u) throw MemoryAccessError(MemoryError::Permission);
        if (zero_length) {
            // §3.4.2.12 requires an actual zero-byte read at the selected
            // address for GET. PUT changes no bytes; the normal protocol
            // completion path still waits for target authorization.
            if (operation==IntegerAtomicOperation::Read) region.storage->read(offset,nullptr,0);
            return {};
        }
        std::vector<uint8_t> previous(width);
        region.storage->read(offset,previous.data(),width);
        const auto next=fetching_atomic_update(previous,operand,compare_or_mask,operation,datatype);
        // One runtime callback contains authorization, load and update. READ
        // returns the old value without an unnecessary write to the storage.
        if (operation!=IntegerAtomicOperation::Read) region.storage->write(offset,next.data(),width);
        return previous;
    }
    void atomic_elements(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,
                         IntegerAtomicOperation operation,IntegerAtomicDatatype datatype,
                         const std::vector<uint8_t>& operands,std::optional<uint16_t> resource_index={},bool relative_addressing=true) {
        const auto element_width=integer_atomic_width(datatype);
        if (offset%element_width) throw MemoryAccessError(MemoryError::Alignment);
        if (operands.size()%element_width) throw std::invalid_argument("incomplete atomic element");
        const auto& region=authorize(job,pid,key,offset,operands.size(),Access::Atomic,resource_index,relative_addressing);
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
    const Region& check_access(const Region& region,uint32_t job,uint16_t pid,uint64_t offset,uint64_t length,
                               Access access,std::optional<uint16_t> resource_index,MemoryAccessOrigin origin) const {
        if (job>0xffffff || (!region.allow_any_job && (!has_job(job) || region.job!=job)))
            throw MemoryAccessError(MemoryError::WrongJob);
        if (region.pid_scope && *region.pid_scope!=pid) throw MemoryAccessError(MemoryError::WrongEndpoint);
        if (resource_index && region.resource_index && resource_index!=region.resource_index)
            throw MemoryAccessError(MemoryError::InvalidKey);
        if (region.local_placement_only && origin!=MemoryAccessOrigin::LocalPlacement)
            throw MemoryAccessError(MemoryError::Permission);
        // A libfabric FI_SEND buffer is not a general FI_REMOTE_READ grant.
        // Its private registration may only feed a locally created rendezvous
        // view. Incoming READ/WRITE keys and ordinary result/posting lookups
        // cannot select this origin (§2.2.10.4 / §3.4.5.3).
        if (region.rendezvous_source_only && origin!=MemoryAccessOrigin::RendezvousSource)
            throw MemoryAccessError(MemoryError::Permission);
        if (!(region.permissions&static_cast<uint8_t>(access))) throw MemoryAccessError(MemoryError::Permission);
        if (offset>region.storage->size() || length>region.storage->size()-offset)
            throw MemoryAccessError(MemoryError::Bounds);
        return region;
    }
    std::shared_ptr<MemoryKeyAllocator> key_allocator_;
    uint64_t next_registration_=0;
    std::set<uint32_t> jobs_;
    std::shared_ptr<const int> authority_=std::make_shared<const int>(0);
    std::map<uint64_t,std::list<Region>> regions_; // Appending a scope preserves other region references.
};
} // namespace UET::SES
