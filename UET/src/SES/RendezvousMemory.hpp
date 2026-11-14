#pragma once
#include "PayloadSource.hpp"

namespace UET::SES {

// A rendezvous view pins LOCAL registration identity, then advertises a
// separate read-only MR key. Reusing the application's old key cannot revive
// the advertised view (§2.2.10.4/Table2-44). No received pointer is involved.
class RegisteredReadPayload final : public PayloadSource {
public:
    RegisteredReadPayload(MemoryRegistry& registry,Region registration,uint32_t job,uint16_t pid,
                          uint16_t resource_index,uint64_t offset,uint32_t length)
        :registry_(registry),registration_(std::move(registration)),job_(job),pid_(pid),
         resource_index_(resource_index),offset_(offset),length_(length) {
        if (registration_.local_placement_only) throw MemoryAccessError(MemoryError::Permission);
        registry_.authorize_registration(registration_,job_,pid_,offset_,length_,Access::Read,resource_index_,
            MemoryAccessOrigin::RendezvousSource);
    }
    uint64_t size() const override { return length_; }
    void read(uint64_t offset,uint8_t* destination,size_t count) const override {
        if (offset>length_ || count>length_-offset) throw MemoryAccessError(MemoryError::Bounds);
        const auto& live=registry_.authorize_registration(registration_,job_,pid_,offset_+offset,count,
            Access::Read,resource_index_,MemoryAccessOrigin::RendezvousSource);
        live.storage->read(offset_+offset,destination,count);
    }
private:
    MemoryRegistry& registry_;
    Region registration_;
    uint32_t job_; uint16_t pid_,resource_index_;
    uint64_t offset_; uint32_t length_;
};

// A metadata-only MR alias owns no additional payload pages. It maps offset0
// to the beginning of this message, while each access still checks the pinned
// application registration above. A WRITE to the alias is never permitted.
class ReadOnlyPayloadStorage final : public MemoryStorage {
public:
    explicit ReadOnlyPayloadStorage(std::shared_ptr<const PayloadSource> source):source_(std::move(source)) {
        if (!source_) throw std::invalid_argument("missing registered source view");
    }
    uint64_t size() const override { return source_->size(); }
    size_t allocated_pages() const override { return 0; }
    void read(uint64_t offset,uint8_t* destination,size_t length) const override { source_->read(offset,destination,length); }
    void write(uint64_t,const uint8_t*,size_t) override { throw MemoryAccessError(MemoryError::Permission); }
private:
    std::shared_ptr<const PayloadSource> source_;
};
} // namespace UET::SES
