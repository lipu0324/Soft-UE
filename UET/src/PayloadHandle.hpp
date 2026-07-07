#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <utility>
#include <vector>

namespace UET {

#ifndef UET_PAYLOAD_POOL_SLOTS
#define UET_PAYLOAD_POOL_SLOTS 1024
#endif

#ifndef UET_PAYLOAD_POOL_BYTES
#define UET_PAYLOAD_POOL_BYTES 4096
#endif

// A small, hardware-friendly descriptor for a payload byte-range.
// - id/gen identify the backing buffer in a pool (software today, DMA/BRAM later).
// - off/len describe a byte range within the backing buffer.
struct PayloadDesc
{
    uint32_t id = 0;
    uint32_t gen = 0;
    uint32_t off = 0;
    uint32_t len = 0;
};

class PayloadPool
{
public:
    static constexpr uint32_t kMaxSlots = UET_PAYLOAD_POOL_SLOTS;
    static constexpr uint32_t kMaxBytes = UET_PAYLOAD_POOL_BYTES;

    static PayloadPool& instance()
    {
        static PayloadPool pool;
        return pool;
    }

    PayloadDesc alloc(size_t len)
    {
        if (len == 0 || len > kMaxBytes) return PayloadDesc{};

        std::lock_guard<std::mutex> lock(mu_);
        if (free_count_ == 0) return PayloadDesc{};

        const uint32_t id = free_ids_[--free_count_];
        auto& slot = slots_[id];
        slot.refs = 1;
        // Bump generation on reuse so stale handles can be detected.
        slot.gen += 1;
        slot.len = static_cast<uint32_t>(len);

        return PayloadDesc{id, slot.gen, 0u, slot.len};
    }

    PayloadDesc alloc_copy(const uint8_t* src, size_t len)
    {
        if (!src || len == 0 || len > kMaxBytes) return PayloadDesc{};

        std::lock_guard<std::mutex> lock(mu_);
        if (free_count_ == 0) return PayloadDesc{};

        const uint32_t id = free_ids_[--free_count_];
        auto& slot = slots_.at(id);
        slot.refs = 1;
        // Bump generation on reuse so stale handles can be detected.
        slot.gen += 1;
        slot.len = static_cast<uint32_t>(len);
        std::memcpy(slot.bytes.data(), src, len);

        return PayloadDesc{id, slot.gen, 0u, slot.len};
    }

    void retain(const PayloadDesc& d)
    {
        if (d.id == 0) return;
        std::lock_guard<std::mutex> lock(mu_);
        if (d.id >= kMaxSlots) return;
        auto& slot = slots_.at(d.id);
        if (slot.gen != d.gen) return;
        slot.refs += 1;
    }

    void release(const PayloadDesc& d)
    {
        if (d.id == 0) return;
        std::lock_guard<std::mutex> lock(mu_);
        if (d.id >= kMaxSlots) return;
        auto& slot = slots_.at(d.id);
        if (slot.gen != d.gen) return;
        if (slot.refs == 0) return;
        slot.refs -= 1;
        if (slot.refs != 0) return;
        slot.len = 0;
        if (free_count_ < kMaxSlots - 1) {
            free_ids_[free_count_++] = d.id;
        }
    }

    const uint8_t* data(const PayloadDesc& d) const
    {
        if (d.id == 0) return nullptr;
        std::lock_guard<std::mutex> lock(mu_);
        if (d.id >= kMaxSlots) return nullptr;
        const auto& slot = slots_.at(d.id);
        if (slot.gen != d.gen) return nullptr;
        if (d.off > slot.len) return nullptr;
        if (static_cast<size_t>(d.off) + static_cast<size_t>(d.len) > slot.len) return nullptr;
        return slot.bytes.data() + d.off;
    }

    uint8_t* data_mut(const PayloadDesc& d)
    {
        if (d.id == 0) return nullptr;
        std::lock_guard<std::mutex> lock(mu_);
        if (d.id >= kMaxSlots) return nullptr;
        auto& slot = slots_.at(d.id);
        if (slot.gen != d.gen) return nullptr;
        if (d.off > slot.len) return nullptr;
        if (static_cast<size_t>(d.off) + static_cast<size_t>(d.len) > slot.len) return nullptr;
        return slot.bytes.data() + d.off;
    }

    size_t size(const PayloadDesc& d) const
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (d.id == 0) return 0;
        if (d.id >= kMaxSlots) return 0;
        const auto& slot = slots_.at(d.id);
        if (slot.gen != d.gen) return 0;
        if (d.off > slot.len) return 0;
        if (static_cast<size_t>(d.off) + static_cast<size_t>(d.len) > slot.len) return 0;
        return static_cast<size_t>(d.len);
    }

private:
    struct Slot
    {
        uint32_t refs{0};
        uint32_t gen{0};
        uint32_t len{0};
        std::array<uint8_t, kMaxBytes> bytes{};
    };

    PayloadPool()
    {
        // slots_[0] is unused to keep id==0 as "null".
        for (uint32_t id = 1; id < kMaxSlots; ++id) {
            free_ids_[free_count_++] = id;
        }
    }

    std::array<Slot, kMaxSlots> slots_{};
    mutable std::mutex mu_;
    std::array<uint32_t, kMaxSlots> free_ids_{};
    uint32_t free_count_{0};
};

// Reference-like payload carrier with cheap copies (descriptor + pool refcount).
// This keeps internal queueing cheap while retaining a handle/descriptor representation
// that can later be mapped to a hardware buffer pool.
class PayloadHandle
{
public:
    PayloadHandle() = default;

    PayloadHandle(const PayloadHandle& other)
        : desc_(other.desc_)
    {
        PayloadPool::instance().retain(desc_);
    }

    PayloadHandle(PayloadHandle&& other) noexcept
        : desc_(other.desc_)
    {
        other.desc_ = PayloadDesc{};
    }

    PayloadHandle& operator=(const PayloadHandle& other)
    {
        if (this == &other) return *this;
        PayloadPool::instance().release(desc_);
        desc_ = other.desc_;
        PayloadPool::instance().retain(desc_);
        return *this;
    }

    PayloadHandle& operator=(PayloadHandle&& other) noexcept
    {
        if (this == &other) return *this;
        PayloadPool::instance().release(desc_);
        desc_ = other.desc_;
        other.desc_ = PayloadDesc{};
        return *this;
    }

    ~PayloadHandle()
    {
        PayloadPool::instance().release(desc_);
    }

    static PayloadHandle alloc(size_t len)
    {
        PayloadHandle h;
        h.desc_ = PayloadPool::instance().alloc(len);
        return h;
    }

    bool empty() const noexcept { return size() == 0; }
    size_t size() const noexcept { return PayloadPool::instance().size(desc_); }

    uint8_t* data() noexcept { return PayloadPool::instance().data_mut(desc_); }
    const uint8_t* data() const noexcept { return PayloadPool::instance().data(desc_); }

    uint8_t operator[](size_t i) const
    {
        const uint8_t* p = data();
        return p ? p[i] : 0;
    }

    void clear() noexcept
    {
        PayloadPool::instance().release(desc_);
        desc_ = PayloadDesc{};
    }

    void allocate(size_t len)
    {
        PayloadPool::instance().release(desc_);
        desc_ = PayloadPool::instance().alloc(len);
    }

    void assign(const uint8_t* first, const uint8_t* last)
    {
        if (!first || !last || last <= first) {
            clear();
            return;
        }
        const size_t len = static_cast<size_t>(last - first);
        PayloadPool::instance().release(desc_);
        desc_ = PayloadPool::instance().alloc_copy(first, len);
    }

    template <class InputIt>
    void assign(InputIt first, InputIt last)
    {
        std::vector<uint8_t> tmp;
        for (auto it = first; it != last; ++it) {
            tmp.push_back(static_cast<uint8_t>(*it));
        }
        PayloadPool::instance().release(desc_);
        desc_ = PayloadPool::instance().alloc_copy(tmp.data(), tmp.size());
    }

    const PayloadDesc& desc() const noexcept { return desc_; }

private:
    PayloadDesc desc_{};
};

} // namespace UET
