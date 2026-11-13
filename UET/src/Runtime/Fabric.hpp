#pragma once
#include "Runtime.hpp"
#include "PacketPort.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <algorithm>
#include <array>
#include <deque>
#include <set>
#include <optional>

namespace UET::Runtime {

struct LinkConfig {
    uint64_t rate_bps = 100000000000ULL;
    Time delay_ns = 1000;
    Time fec_delay_ns = 0;
    size_t mtu = 9216; // Complete frame limit; no hidden fragmentation.
    size_t buffer_bytes = 65536; // Independent capacity per traffic class, including in-service bytes.
    uint32_t drop_ppm = 0;
    Time extra_delay_ns = 0;
    std::array<std::optional<size_t>,8> ecn_threshold_bytes{}; // null disables; zero marks every ECT packet.
    std::array<uint16_t,8> traffic_class_weights{{1,1,1,1,1,1,1,1}};
    size_t scheduling_quantum_bytes=256; // Deficit round robin, local switch policy.
    std::optional<NetworkLayer::TrimmingOptions> trimming;
};

struct LinkStats {
    uint64_t packets = 0, bytes = 0, dropped = 0, delivered = 0;
    size_t queued_bytes = 0, peak_queue_bytes = 0;
    std::array<size_t,8> queued_by_class{},peak_by_class{};
    uint64_t ecn_marked=0;
    uint64_t trimmed=0,trimmed_bytes=0;
};

// A deterministic packet fabric. Switches store and forward complete frames.
// Routes are shortest-hop ECMP with a stable per-frame entropy selection.
// Traffic classes use independent byte buffers and deficit-round-robin service.
// ECN is evaluated at dequeue, as assumed by NSCC (§3.6.4.1). LLR/CBFC are separate.
class Fabric {
public:
    class Port final : public IPacketPort {
    public:
        bool provides_transmit_timing() const override { return true; }
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
        if (config.trimming) config.trimming->validate();
        if (from == to || !nodes_.count(from) || !nodes_.count(to) ||
            !config.rate_bps || !config.mtu || config.buffer_bytes < config.mtu ||
            config.drop_ppm > 1000000 || !config.scheduling_quantum_bytes ||
            std::any_of(config.traffic_class_weights.begin(),config.traffic_class_weights.end(),[](uint16_t weight) { return !weight; }) ||
            config.scheduling_quantum_bytes>UINT32_MAX || config.mtu>UINT32_MAX || edges_.count({from,to}))
            throw std::invalid_argument("invalid directed link");
        edges_.emplace(std::make_pair(from,to), Edge{config});
    }
    void set_link_up(uint32_t from, uint32_t to, bool up) {
        auto& edge=edges_.at({from,to});
        if (edge.up && !up) { ++edge.generation; discard_waiting(edge,{from,to}); }
        edge.up = up;
        trace_.record(from, up ? "link_up" : "link_down", to);
    }
    const LinkStats& stats(uint32_t from, uint32_t to) const { return edges_.at({from,to}).stats; }
    void set_capture(std::function<void(Time,const Frame&)> capture) { capture_=std::move(capture); }
    void set_link_capture(std::function<void(Time,uint32_t,uint32_t,const Frame&)> capture) { link_capture_=std::move(capture); }

private:
    struct QueuedFrame {
        std::shared_ptr<Frame> frame;
        std::shared_ptr<std::vector<uint32_t>> path;
        size_t hop;
    };
    struct Edge {
        LinkConfig config;
        LinkStats stats{};
        bool up = true;
        bool transmitting=false;
        uint64_t generation=0;
        std::array<std::deque<QueuedFrame>,8> queues;
        std::array<uint64_t,8> deficits{};
        size_t scheduler_class=0;
        bool new_scheduler_visit=true;
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
    std::function<void(Time,uint32_t,uint32_t,const Frame&)> link_capture_;

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
            auto local_frame=frame; prepare_first_transmission(local_frame,loop_.now());
            local_frame.first_byte_arrival_ns=loop_.now(); local_frame.has_arrival_timestamp=true;
            schedule(loop_.now(), [this, local_frame] { deliver(local_frame); });
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
        auto size=frame->bytes.size();
        if (edge.config.trimming) {
            // Reclassify from the actual DSCP on every configured ingress.
            // In particular, a trim notification received from another switch
            // must not depend on the sender carrying our local Frame metadata.
            if (const auto dscp=NetworkLayer::UetWireCodec::packet_dscp(frame->bytes)) {
                if (edge.config.trimming->is_trimmed(*dscp)) frame->traffic_class=edge.config.trimming->trimmed_traffic_class;
                else if (*dscp==edge.config.trimming->control_dscp) frame->traffic_class=1;
                else if (*dscp==edge.config.trimming->trimmable_dscp || *dscp==edge.config.trimming->no_trim_dscp)
                    frame->traffic_class=0;
            }
        }
        auto traffic_class=frame->traffic_class;
        const auto drop=[&] {
            reject_before_transmission(*frame,loop_.now());
            ++stats.dropped;
            trace_.record(key.first, "link_drop", key.second);
        };
        if (!edge.up) { drop(); return; }
        if (size>edge.config.buffer_bytes-stats.queued_by_class[traffic_class]) {
            bool trimmed=false;
            if (edge.config.trimming) {
                try {
                    trimmed=NetworkLayer::UetWireCodec::trim_packet(frame->bytes,*edge.config.trimming,hop+1==path->size());
                } catch (const std::invalid_argument&) { /* Invalid IP cannot become a trim notification. */ }
            }
            if (!trimmed) { drop(); return; }
            ++stats.trimmed; stats.trimmed_bytes+=size-frame->bytes.size();
            trace_.record(key.first,"packet_trim",key.second);
            size=frame->bytes.size();
            traffic_class=edge.config.trimming->trimmed_traffic_class;
            frame->traffic_class=traffic_class;
            // §4.1: trimmed traffic is a new admission into its own queue,
            // and still drops normally if that queue has insufficient space.
            if (size>edge.config.buffer_bytes-stats.queued_by_class[traffic_class]) { drop(); return; }
        }
        stats.queued_bytes+=size; stats.queued_by_class[traffic_class]+=size;
        stats.peak_queue_bytes=std::max(stats.peak_queue_bytes,stats.queued_bytes);
        stats.peak_by_class[traffic_class]=std::max(stats.peak_by_class[traffic_class],stats.queued_by_class[traffic_class]);
        ++stats.packets; stats.bytes+=size;
        edge.queues[traffic_class].push_back({std::move(frame),std::move(path),hop});
        serialize_next(key);
    }
    void discard_waiting(Edge& edge,const std::pair<uint32_t,uint32_t>& key) {
        for (size_t traffic_class=0;traffic_class<8;++traffic_class) {
            auto& queue=edge.queues[traffic_class];
            while (!queue.empty()) {
                const auto size=queue.front().frame->bytes.size();
                reject_before_transmission(*queue.front().frame,loop_.now()); queue.pop_front();
                edge.stats.queued_bytes-=size; edge.stats.queued_by_class[traffic_class]-=size;
                ++edge.stats.dropped; trace_.record(key.first,"link_drop",key.second);
            }
            edge.deficits[traffic_class]=0;
        }
    }
    size_t choose_class(Edge& edge) {
        size_t active=0,only_class=0;
        for (size_t traffic_class=0;traffic_class<8;++traffic_class)
            if (!edge.queues[traffic_class].empty()) { ++active; only_class=traffic_class; }
        if (!active) return 8;
        if (active==1) {
            // Empty classes accumulate no credit. Avoid MTU/quantum rounds
            // when only one queue exists; this preserves inexpensive bulk runs.
            edge.scheduler_class=(only_class+1)%8; edge.deficits[only_class]=0;
            edge.new_scheduler_visit=true;
            return only_class;
        }
        for (;;) {
            const auto traffic_class=edge.scheduler_class;
            auto& queue=edge.queues[traffic_class]; auto& deficit=edge.deficits[traffic_class];
            if (queue.empty()) deficit=0;
            else {
                const auto size=queue.front().frame->bytes.size();
                if (edge.new_scheduler_visit) {
                    const auto quantum=uint64_t{edge.config.scheduling_quantum_bytes}*edge.config.traffic_class_weights[traffic_class];
                    deficit+=quantum;
                    edge.new_scheduler_visit=false;
                }
                if (deficit>=size) { deficit-=size; return traffic_class; }
            }
            edge.scheduler_class=(traffic_class+1)%8;
            edge.new_scheduler_visit=true;
        }
    }
    void serialize_next(const std::pair<uint32_t,uint32_t>& key) {
        auto& edge=edges_.at(key);
        if (edge.transmitting || !edge.up) return;
        const auto traffic_class=choose_class(edge);
        if (traffic_class==8) return;
        auto item=std::move(edge.queues[traffic_class].front()); edge.queues[traffic_class].pop_front();
        auto frame=std::move(item.frame); auto path=std::move(item.path); const auto hop=item.hop;
        const auto size=frame->bytes.size();
        const auto threshold=edge.config.ecn_threshold_bytes[traffic_class];
        if (threshold && edge.stats.queued_by_class[traffic_class]>=*threshold) {
            try {
                if (NetworkLayer::UetWireCodec::mark_ecn(frame->bytes)) {
                    ++edge.stats.ecn_marked; trace_.record(key.first,"ecn_mark",key.second);
                }
            } catch (const std::invalid_argument&) { /* Non-IP test frames are not ECN-capable. */ }
        }
        prepare_first_transmission(*frame,loop_.now());
        if (link_capture_) link_capture_(loop_.now(),key.first,key.second,*frame);
        // Random link loss still consumes serialization and wire capacity.
        // Queue rejection above has its separate pre-transmission outcome.
        const bool lost_on_wire=random_.chance(edge.config.drop_ppm);
        const auto numerator = static_cast<unsigned __int128>(size) * 8 * 1000000000ULL;
        const auto serial = (numerator + edge.config.rate_bps - 1) / edge.config.rate_bps;
        if (serial > UINT64_MAX) throw std::overflow_error("serialization time overflow");
        const auto finish=add_time(loop_.now(),static_cast<Time>(serial));
        const auto delays=add_time(add_time(edge.config.delay_ns,edge.config.fec_delay_ns),edge.config.extra_delay_ns);
        const auto arrival=add_time(finish,delays),first_byte_arrival=add_time(loop_.now(),delays);
        const auto generation=edge.generation;
        edge.transmitting=true;
        schedule(finish,[this,key,size,traffic_class] {
            auto& edge=edges_.at(key); edge.stats.queued_bytes-=size; edge.stats.queued_by_class[traffic_class]-=size;
            edge.transmitting=false; serialize_next(key);
        });
        schedule(arrival, [this, key, frame, path, hop, generation, first_byte_arrival, lost_on_wire] {
            auto& edge = edges_.at(key);
            if (lost_on_wire || !edge.up || edge.generation!=generation) { ++edge.stats.dropped; trace_.record(key.first,"link_drop",key.second); return; }
            ++edge.stats.delivered;
            frame->first_byte_arrival_ns=first_byte_arrival; frame->has_arrival_timestamp=true;
            if (hop + 1 == path->size()) deliver(*frame);
            else forward(frame, path, hop + 1);
        });
    }
};
} // namespace UET::Runtime
