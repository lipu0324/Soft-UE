#pragma once
#include "Runtime.hpp"
#include "PacketPort.hpp"
#include <algorithm>
#include <array>
#include <deque>
#include <set>

namespace UET::Runtime {

struct LinkConfig {
    uint64_t rate_bps = 100000000000ULL;
    Time delay_ns = 1000;
    Time fec_delay_ns = 0;
    size_t mtu = 9216; // Complete frame limit; no hidden fragmentation.
    size_t buffer_bytes = 65536;
    uint32_t drop_ppm = 0;
    Time extra_delay_ns = 0;
};

struct LinkStats {
    uint64_t packets = 0, bytes = 0, dropped = 0, delivered = 0;
    size_t queued_bytes = 0, peak_queue_bytes = 0;
};

// A deterministic packet fabric. Switches store and forward complete frames.
// Routes are shortest-hop ECMP with a stable per-frame entropy selection.
// This base model deliberately does not advertise CMS, LLR or CBFC support.
class Fabric {
public:
    class Port final : public IPacketPort {
    public:
        SendResult try_send(const Frame& frame) override {
            if (frame.source != node_) throw std::invalid_argument("frame source does not own port");
            return fabric_.send(frame);
        }
        void set_receiver(Receiver receiver) override { receiver_ = std::move(receiver); }
        void set_writable_handler(Writable callback) override { writable_ = std::move(callback); }
    private:
        friend class Fabric;
        Port(Fabric& fabric, uint32_t node) : fabric_(fabric), node_(node) {}
        Fabric& fabric_;
        uint32_t node_;
        Receiver receiver_;
        Writable writable_; // This drop-tail backend never returns WouldBlock.
    };

    Fabric(EventLoop& loop, Trace& trace, uint64_t seed) : loop_(loop), trace_(trace), random_(seed) {}
    ~Fabric() { lifetime_.reset(); for (auto id : timers_) loop_.cancel(id); }
    Fabric(const Fabric&) = delete;
    Fabric& operator=(const Fabric&) = delete;

    Port& add_host(uint32_t node) {
        if (ports_.count(node)) throw std::invalid_argument("duplicate host");
        auto port = std::unique_ptr<Port>(new Port(*this, node));
        auto& reference = *port;
        ports_.emplace(node, std::move(port));
        nodes_.insert(node);
        return reference;
    }
    void add_switch(uint32_t node) {
        if (!nodes_.insert(node).second) throw std::invalid_argument("duplicate node");
    }
    void add_link(uint32_t from, uint32_t to, const LinkConfig& config) {
        if (from == to || !nodes_.count(from) || !nodes_.count(to) ||
            !config.rate_bps || !config.mtu || config.buffer_bytes < config.mtu ||
            config.drop_ppm > 1000000 || edges_.count({from,to}))
            throw std::invalid_argument("invalid directed link");
        edges_.emplace(std::make_pair(from,to), Edge{config});
    }
    void set_link_up(uint32_t from, uint32_t to, bool up) {
        edges_.at({from,to}).up = up;
        trace_.record(from, up ? "link_up" : "link_down", to);
    }
    const LinkStats& stats(uint32_t from, uint32_t to) const { return edges_.at({from,to}).stats; }
    void set_capture(std::function<void(Time,const Frame&)> capture) { capture_=std::move(capture); }

private:
    struct Edge {
        LinkConfig config;
        LinkStats stats{};
        Time available = 0;
        bool up = true;
    };
    EventLoop& loop_;
    Trace& trace_;
    Random random_;
    std::set<uint32_t> nodes_;
    std::map<uint32_t, std::unique_ptr<Port>> ports_;
    std::map<std::pair<uint32_t,uint32_t>, Edge> edges_;
    std::set<TimerId> timers_;
    std::shared_ptr<int> lifetime_ = std::make_shared<int>(0);
    std::function<void(Time,const Frame&)> capture_;

    void schedule(Time when, std::function<void()> callback) {
        auto id = std::make_shared<TimerId>(0);
        std::weak_ptr<int> life = lifetime_;
        *id = loop_.at(when, [this, id, life, callback=std::move(callback)] {
            if (life.expired()) return;
            timers_.erase(*id);
            callback();
        });
        timers_.insert(*id);
    }
    std::vector<uint32_t> route(uint32_t source, uint32_t target, uint16_t entropy) const {
        std::map<uint32_t, size_t> distance{{target,0}};
        std::deque<uint32_t> pending{target};
        while (!pending.empty()) {
            const auto node = pending.front(); pending.pop_front();
            for (const auto& item : edges_) {
                if (item.first.second == node && item.second.up && !distance.count(item.first.first)) {
                    distance[item.first.first] = distance[node] + 1;
                    pending.push_back(item.first.first);
                }
            }
        }
        if (!distance.count(source)) return {};
        std::vector<uint32_t> path{source};
        while (path.back() != target) {
            const auto node = path.back();
            std::vector<uint32_t> choices;
            for (const auto& item : edges_)
                if (item.first.first == node && item.second.up && distance.count(item.first.second) &&
                    distance.at(item.first.second) + 1 == distance.at(node)) choices.push_back(item.first.second);
            if (choices.empty()) return {};
            path.push_back(choices[entropy % choices.size()]);
        }
        return path;
    }
    SendResult send(const Frame& frame) {
        if (!ports_.count(frame.destination) || frame.bytes.empty() || frame.traffic_class > 7)
            return SendResult::NoRoute;
        const auto path = route(frame.source, frame.destination, frame.entropy);
        if (path.empty()) return SendResult::NoRoute;
        for (size_t i=1; i<path.size(); ++i)
            if (frame.bytes.size() > edges_.at({path[i-1],path[i]}).config.mtu) return SendResult::TooLarge;
        trace_.record(frame.source, "fabric_tx", frame.bytes.size());
        if (capture_) capture_(loop_.now(),frame);
        if (path.size() == 1) {
            schedule(loop_.now(), [this, frame] { deliver(frame); });
        } else forward(std::make_shared<Frame>(frame), std::make_shared<std::vector<uint32_t>>(path), 1);
        return SendResult::Accepted;
    }
    void deliver(const Frame& frame) {
        auto found = ports_.find(frame.destination);
        if (found != ports_.end() && found->second->receiver_) {
            trace_.record(frame.destination, "fabric_rx", frame.bytes.size());
            // Copy the callback: receiving may detach/destroy the host.
            const auto callback = found->second->receiver_;
            callback(frame);
        }
    }
    void forward(std::shared_ptr<Frame> frame, std::shared_ptr<std::vector<uint32_t>> path, size_t hop) {
        const auto key = std::make_pair((*path)[hop-1], (*path)[hop]);
        auto& edge = edges_.at(key);
        auto& stats = edge.stats;
        const auto size = frame->bytes.size();
        if (!edge.up || size > edge.config.buffer_bytes - stats.queued_bytes || random_.chance(edge.config.drop_ppm)) {
            ++stats.dropped;
            trace_.record(key.first, "link_drop", key.second);
            return;
        }
        const auto numerator = static_cast<unsigned __int128>(size) * 8 * 1000000000ULL;
        const auto serial = (numerator + edge.config.rate_bps - 1) / edge.config.rate_bps;
        if (serial > UINT64_MAX) throw std::overflow_error("serialization time overflow");
        const auto finish = add_time(std::max(loop_.now(), edge.available), static_cast<Time>(serial));
        const auto arrival = add_time(add_time(add_time(finish, edge.config.delay_ns), edge.config.fec_delay_ns), edge.config.extra_delay_ns);
        edge.available = finish;
        stats.queued_bytes += size;
        stats.peak_queue_bytes = std::max(stats.peak_queue_bytes, stats.queued_bytes);
        ++stats.packets; stats.bytes += size;
        schedule(finish, [this, key, size] { edges_.at(key).stats.queued_bytes -= size; });
        schedule(arrival, [this, key, frame, path, hop] {
            auto& edge = edges_.at(key);
            if (!edge.up) { ++edge.stats.dropped; trace_.record(key.first,"link_drop",key.second); return; }
            ++edge.stats.delivered;
            if (hop + 1 == path->size()) deliver(*frame);
            else forward(frame, path, hop + 1);
        });
    }
};
} // namespace UET::Runtime
