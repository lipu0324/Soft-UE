#pragma once
#include "PdcEvents.hpp"
#include "RetiredSemanticMessages.hpp"
#include "RetiredSemanticReceives.hpp"
#include "ReceiveHandles.hpp"
#include "RetryTiming.hpp"
#include "../PDS/ReceiveDiagnostics.hpp"
#include "../PDS/PsnRangeConfiguration.hpp"
#include "../PDS/PdcMapping.hpp"
#include "../SES/MemoryKeyAllocator.hpp"

#include <chrono>
#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <queue>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

struct PDC_SES_req;
namespace UET::CMS { class ICongestionControl; }
namespace UET::Runtime {

using Time = uint64_t; // Integer nanoseconds in both runtime implementations.
using TimerId = uint64_t;
constexpr Time kMillisecond = 1000000;

inline Time add_time(Time a, Time b) {
    if (b > std::numeric_limits<Time>::max() - a)
        throw std::overflow_error("simulation time overflow");
    return a + b;
}

struct IClock {
    virtual ~IClock() = default;
    virtual Time now() const = 0;
};

struct ITimerQueue {
    virtual ~ITimerQueue() = default;
    virtual TimerId at(Time when, std::function<void()> callback) = 0;
    virtual bool cancel(TimerId id) = 0;
};

// Resource refusal is typed: message bookkeeping and synchronized-group
// bookkeeping have distinct mandatory PDS NACKs (Table3-68).
enum class SemanticAdmission { Rejected, ExistingMessage, ReservedMessage, ReservedPacket, NoSynchronizationState };
// Injected per host. It outlives that host and its PDCs. wake must only enqueue
// work, never re-enter a protocol state machine from a timer callback.
struct Services {
    IClock& clock;
    ITimerQueue& timers;
    std::function<void()> wake;
    Time rto_ns = kMillisecond; // UE 1.1 supports 0..8 s at 128 ns granularity or finer.
    // §3.5.5 / §3.5.12.7: 0..14 are finite counts; 15 means infinite.
    // No separate NACK limit is enabled, so this budget counts both causes.
    uint8_t maximum_packet_retries=kDefaultRetryLimit;
    uint64_t initial_sequence_seed=42; // Injected plaintext PRNG seed; TSS start negotiation is separate.
    // Local SES credits, checked before PDS accepts a data PSN. Reserving a
    // message slot must not match a buffer, touch MR memory, or send a reply.
    std::function<SemanticAdmission(const PDC_SES_req&)> semantic_admission;
    std::function<void(const PDC_SES_req&)> cancel_semantic_reservation;
    // §3.5.5 / §3.5.8.3: a lost SYN remains potentially live in the network.
    // Plaintext connections wait this long before closing; authenticated
    // anti-replay paths may explicitly configure zero when they are active.
    Time syn_retransmission_safety_time = 65*kMillisecond;
    // This callback must enqueue an event, never synchronously re-enter SES.
    std::function<void(const PdcEvent&)> pdc_event;
    // Simulator resource policy, not protocol constants. Each direction owns
    // an independent PDC ID pool; tests can exhaust small pools reproducibly.
    uint16_t initiator_context_limit = 511; // ID zero is reserved (§3.5.8.2).
    uint16_t target_context_limit = 512;
    size_t pending_request_limit = 16384;
    Time pending_request_timeout = 100*kMillisecond;
    // §3.5.12.7 permits one to four NACK delays, selected by code. Groups
    // are normal recovery, resource pressure, SES processing, and spare.
    std::array<Time,4> nack_retransmission_delays_ns{{0,2*kMillisecond,kMillisecond,0}};
    bool standard_wire=true;
    uint16_t default_wire_entropy=0; // Fixed path when CMS is disabled.
    std::ostream* diagnostic_output=nullptr; // Structured Trace is independent of textual diagnostics.
    CMS::ICongestionControl* congestion_control=nullptr; // Optional explicit CMS configuration.
    uint32_t mpr_zero_override=0; // §3.5.11.13: zero means ignore received MPR=0.
    PDS::PsnRangeConfiguration psn_ranges;
    PDS::PdcMappingConfiguration pdc_mapping;
    // UE 1.1 Table 3-35: fabric-wide READ return-data threshold, in bytes.
    // Each response carries at most one Payload MTU; a message can span many.
    uint32_t max_ack_data_size=16;
    // Payload MTU shared by SES packetization and PDS READ-response recovery.
    // A READ request has no payload from which PDS could infer this length.
    uint32_t semantic_payload_mtu=1024;
    uint16_t next_probe_opaque=0; // Host-scoped identifier persists across PDC reuse.
    bool enable_automatic_window_probes=true; // May be disabled for isolated admission experiments.
    bool actual_transmit_notifications=false; // Set by a port with a first-bit departure boundary.
    uint64_t next_pdc_incarnation=0;
    PDS::ReceiveErrorCounters pds_error_counters;
    // Per-FEP SES authority survives replacing the Endpoint on this host.
    // Use a 64-bit cursor so exhaustion of the 32-bit wire token cannot wrap
    // silently onto a stale deferred transaction. Simulation may inject it.
    uint64_t next_semantic_restart_token=1;
    // A 16-bit synchronized group may be reused only after all members are
    // acknowledged. Keep fresh allocation monotonic across SES replacement.
    uint32_t next_synchronization_group_id=0;
    // §3.5.23: packet IDs are locally unique, including after replacing SES.
    // Exhaust the 32-bit wire space rather than aliasing a delayed response.
    uint64_t next_rudi_packet_id=0;
    size_t rudi_packet_limit=4096; // Initiator storage policy; target has no recovery state.
    // This host has one active native SES adapter. Its MID cursor and retired
    // leases outlive that adapter, including optimized local TX cookies.
    std::weak_ptr<int> active_semantic_endpoint;
    uint16_t semantic_message_cursor=0;
    RetiredSemanticMessages retired_semantic_messages;
    // Target READ return tokens are a separate namespace from source MIDs.
    // They may survive SES replacement in the reverse PDC transmit queue.
    uint16_t semantic_response_cursor=0;
    RetiredSemanticMessages retired_semantic_responses;
    RetiredSemanticReceives retired_semantic_receives;
    // Native private registries share only allocation history across SES
    // replacement. Registrations and their local authority remain separate.
    std::shared_ptr<SES::MemoryKeyAllocator> semantic_memory_keys=std::make_shared<SES::MemoryKeyAllocator>();
    ReceiveHandleAllocator receive_handle_allocator; // Shared across every PDC incarnation on this Host.

};

class EventLoop final : public IClock, public ITimerQueue {
public:
    EventLoop()=default;
    explicit EventLoop(const IClock& live_clock):live_clock_(&live_clock) {}
    Time now() const override { return live_clock_?live_clock_->now():now_; }
    TimerId at(Time when, std::function<void()> callback) override {
        if (!callback) throw std::invalid_argument("invalid event time or callback");
        const auto current=now();
        if (when<current) {
            if (!live_clock_) throw std::invalid_argument("invalid event time or callback");
            // A real caller can be descheduled between reading the clock and
            // scheduling an immediate event. Dispatch it at the current time;
            // virtual simulations still reject scheduling into their past.
            when=current;
        }
        if (next_id_ == std::numeric_limits<TimerId>::max()) throw std::overflow_error("event sequence exhausted");
        const auto id = ++next_id_;
        const Key key{when,id};
        events_.emplace(key,std::move(callback));
        index_.emplace(id,key);
        return id;
    }
    TimerId after(Time delay, std::function<void()> callback) {
        return at(add_time(now(),delay),std::move(callback));
    }
    bool cancel(TimerId id) override {
        const auto found = index_.find(id);
        if (found == index_.end()) return false;
        events_.erase(found->second);
        index_.erase(found);
        return true;
    }
    size_t pending() const { return events_.size(); }
    uint64_t executed() const { return executed_; }
    size_t run_until(Time limit, size_t budget = 1000000) {
        if (limit < now_) throw std::invalid_argument("time cannot move backwards");
        if (live_clock_ && limit>live_clock_->now())
            throw std::invalid_argument("live events cannot run ahead of their clock");
        size_t count = 0;
        while (!events_.empty() && events_.begin()->first.first <= limit) {
            if (count == budget) throw std::runtime_error("event budget exhausted");
            auto found = events_.begin();
            const auto key = found->first;
            auto callback = std::move(found->second);
            index_.erase(key.second);
            events_.erase(found);
            now_ = std::max(now_,key.first);
            ++count; ++executed_;
            callback();
        }
        now_ = limit;
        return count;
    }
    size_t run(size_t budget = 1000000) {
        size_t count = 0;
        while (!events_.empty()) {
            if (count == budget) throw std::runtime_error("event budget exhausted");
            count += run_until(events_.begin()->first.first,budget-count);
        }
        return count;
    }
private:
    using Key = std::pair<Time,TimerId>;
    Time now_ = 0;
    const IClock* live_clock_=nullptr;
    TimerId next_id_ = 0;
    uint64_t executed_ = 0;
    std::map<Key,std::function<void()>> events_;
    std::map<TimerId,Key> index_;
};

// The same timer engine can be driven explicitly from a real monotonic clock.
// It never creates a background thread; applications/providers call progress().
class RealtimeRuntime : public IClock {
public:
    RealtimeRuntime() : epoch_(std::chrono::steady_clock::now()),events_(*this) {}
    // A caller-owned elapsed clock makes late manual progress reproducible
    // without sleeping or reading wall time in a deterministic regression.
    explicit RealtimeRuntime(const IClock& elapsed_clock) : elapsed_clock_(&elapsed_clock),events_(*this) {}
    // events_ follows this object's clock; copying or moving would leave the
    // event queue referring to a different runtime instance.
    RealtimeRuntime(const RealtimeRuntime&)=delete;
    RealtimeRuntime& operator=(const RealtimeRuntime&)=delete;
    RealtimeRuntime(RealtimeRuntime&&)=delete;
    RealtimeRuntime& operator=(RealtimeRuntime&&)=delete;
    EventLoop& events() { return events_; }
    Time now() const override {
        return elapsed_clock_?elapsed_clock_->now():static_cast<Time>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - epoch_).count());
    }
    void progress(size_t budget = 1000000) {
        // UE3.5.14.5 starts a new timeout from the actual retransmission.
        // Keep deadline ordering, but callbacks observe the live injected
        // clock, not their historical deadline. A delayed progress call must
        // not replay all elapsed retry intervals as back-to-back sends.
        events_.run_until(now(), budget);
    }
private:
    std::chrono::steady_clock::time_point epoch_;
    const IClock* elapsed_clock_=nullptr;
    EventLoop events_;
};

// Stable across standard-library implementations (unlike uniform_distribution).
class Random {
public:
    explicit Random(uint64_t seed) : state_(seed) {}
    uint64_t next() {
        auto z = (state_ += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    bool chance(uint32_t parts_per_million) {
        if (parts_per_million > 1000000) throw std::invalid_argument("invalid probability");
        // Rejection avoids modulo bias; decisions remain platform independent.
        constexpr uint64_t bound = 1000000;
        constexpr uint64_t threshold = -bound % bound;
        uint64_t value;
        do { value = next(); } while (value < threshold);
        return value % bound < parts_per_million;
    }
private:
    uint64_t state_;
};

struct TraceEvent {
    Time time;
    uint64_t sequence;
    uint32_t node;
    std::string event;
    uint64_t value;
};

class Trace {
public:
    explicit Trace(const IClock& clock, size_t limit = 1000000) : clock_(clock), limit_(limit) {}
    void record(uint32_t node, std::string event, uint64_t value = 0) {
        if (!limit_) return; // Explicitly disabled for long-running provider use.
        if (events_.size() == limit_) throw std::runtime_error("trace record budget exhausted");
        events_.push_back({clock_.now(), events_.size(), node, std::move(event), value});
    }
    const std::vector<TraceEvent>& events() const { return events_; }
private:
    const IClock& clock_;
    size_t limit_;
    std::vector<TraceEvent> events_;
};

} // namespace UET::Runtime
