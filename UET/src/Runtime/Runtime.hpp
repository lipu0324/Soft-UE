#pragma once
#include "PdcEvents.hpp"

#include <chrono>
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

// Injected per host. It outlives that host and its PDCs. wake must only enqueue
// work, never re-enter a protocol state machine from a timer callback.
struct Services {
    IClock& clock;
    ITimerQueue& timers;
    std::function<void()> wake;
    uint16_t rto_ms = 1;
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
    Time resource_nack_retry_delay = 2*kMillisecond;
    bool standard_wire=true;
    uint16_t default_wire_entropy=0; // Fixed path when CMS is disabled.
    std::ostream* diagnostic_output=nullptr; // Structured Trace is independent of textual diagnostics.
    CMS::ICongestionControl* congestion_control=nullptr; // Optional explicit CMS configuration.
    uint32_t mpr_zero_override=0; // §3.5.11.13: zero means ignore received MPR=0.
    uint16_t next_probe_opaque=0; // Host-scoped identifier persists across PDC reuse.
    bool enable_automatic_window_probes=true; // May be disabled for isolated admission experiments.
    bool actual_transmit_notifications=false; // Set by a port with a first-bit departure boundary.
    uint64_t next_pdc_incarnation=0;
};

class EventLoop final : public IClock, public ITimerQueue {
public:
    Time now() const override { return now_; }
    TimerId at(Time when, std::function<void()> callback) override {
        if (when < now_ || !callback) throw std::invalid_argument("invalid event time or callback");
        if (next_id_ == std::numeric_limits<TimerId>::max()) throw std::overflow_error("event sequence exhausted");
        const auto id = ++next_id_;
        const Key key{when,id};
        events_.emplace(key,std::move(callback));
        index_.emplace(id,key);
        return id;
    }
    TimerId after(Time delay, std::function<void()> callback) {
        return at(add_time(now_,delay),std::move(callback));
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
        size_t count = 0;
        while (!events_.empty() && events_.begin()->first.first <= limit) {
            if (count == budget) throw std::runtime_error("event budget exhausted");
            auto found = events_.begin();
            const auto key = found->first;
            auto callback = std::move(found->second);
            index_.erase(key.second);
            events_.erase(found);
            now_ = key.first;
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
    TimerId next_id_ = 0;
    uint64_t executed_ = 0;
    std::map<Key,std::function<void()>> events_;
    std::map<TimerId,Key> index_;
};

// The same timer engine can be driven explicitly from a real monotonic clock.
// It never creates a background thread; applications/providers call progress().
class RealtimeRuntime {
public:
    RealtimeRuntime() : epoch_(std::chrono::steady_clock::now()) {}
    EventLoop& events() { return events_; }
    void progress(size_t budget = 1000000) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - epoch_).count();
        events_.run_until(static_cast<Time>(elapsed), budget);
    }
private:
    std::chrono::steady_clock::time_point epoch_;
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
