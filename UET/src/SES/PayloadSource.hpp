#pragma once
#include "MemoryRegistry.hpp"
#include <functional>
#include <utility>

namespace UET::SES {

// Application-side bytes, never a remote address. A source remains alive until
// SES has copied its final fragment into PDS-owned packet storage. Readers in
// simulation must be deterministic, must not re-enter the endpoint and must
// not block or consult wall time.
class PayloadSource {
public:
    virtual ~PayloadSource()=default;
    virtual uint64_t size() const=0;
    virtual void read(uint64_t offset,uint8_t* destination,size_t length) const=0;
};

class VectorPayload final : public PayloadSource {
public:
    explicit VectorPayload(std::vector<uint8_t> bytes):bytes_(std::move(bytes)) {}
    uint64_t size() const override { return bytes_.size(); }
    void read(uint64_t offset,uint8_t* destination,size_t length) const override {
        if (offset>bytes_.size() || length>bytes_.size()-offset) throw std::out_of_range("payload range");
        if (length && !destination) throw std::invalid_argument("null payload destination");
        if (length) std::memcpy(destination,bytes_.data()+offset,length);
    }
private:
    std::vector<uint8_t> bytes_;
};

// A restarted transaction reads a checked suffix of its original source.
// No full-message copy is made; ownership stays shared with the transaction.
class SlicedPayload final : public PayloadSource {
public:
    SlicedPayload(std::shared_ptr<const PayloadSource> original,uint64_t offset,uint64_t length)
        :original_(std::move(original)),offset_(offset),length_(length) {
        if (!original_ || offset>original_->size() || length>original_->size()-offset)
            throw std::out_of_range("payload slice range");
    }
    uint64_t size() const override { return length_; }
    void read(uint64_t offset,uint8_t* destination,size_t length) const override {
        if (offset>length_ || length>length_-offset) throw std::out_of_range("payload slice range");
        original_->read(offset_+offset,destination,length);
    }
private:
    std::shared_ptr<const PayloadSource> original_;
    uint64_t offset_,length_;
};

class StoragePayload final : public PayloadSource {
public:
    StoragePayload(std::shared_ptr<const MemoryStorage> storage,uint64_t offset,uint64_t length)
        :storage_(std::move(storage)),offset_(offset),length_(length) {
        if (!storage_ || offset>storage_->size() || length>storage_->size()-offset)
            throw std::out_of_range("payload storage range");
    }
    uint64_t size() const override { return length_; }
    void read(uint64_t offset,uint8_t* destination,size_t length) const override {
        if (offset>length_ || length>length_-offset) throw std::out_of_range("payload range");
        storage_->read(offset_+offset,destination,length);
    }
private:
    std::shared_ptr<const MemoryStorage> storage_;
    uint64_t offset_,length_;
};

// A scenario can describe a large logical message without allocating it.
// The callback fills only the requested fragment; lifetime and purity are the
// caller's responsibility, just as for a locally registered application buffer.
class GeneratedPayload final : public PayloadSource {
public:
    using Reader=std::function<void(uint64_t,uint8_t*,size_t)>;
    GeneratedPayload(uint64_t length,Reader reader):length_(length),reader_(std::move(reader)) {
        if (!reader_) throw std::invalid_argument("missing payload reader");
    }
    uint64_t size() const override { return length_; }
    void read(uint64_t offset,uint8_t* destination,size_t length) const override {
        if (offset>length_ || length>length_-offset) throw std::out_of_range("payload range");
        if (length && !destination) throw std::invalid_argument("null payload destination");
        reader_(offset,destination,length);
    }
private:
    uint64_t length_;
    Reader reader_;
};
} // namespace UET::SES
