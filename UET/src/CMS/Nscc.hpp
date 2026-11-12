#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace UET::CMS {

// Network-signaled congestion control (NSCC), UE 1.1 Table 3-97. Times are
// integer nanoseconds. The proportional gain converts that unit explicitly;
// feeding seconds to one formula and nanoseconds to another changes the law.
struct NsccConfig {
    uint64_t configured_base_rtt_ns=12000;
    uint64_t sender_bytes_per_second=12500000000ULL;
    uint64_t receiver_bytes_per_second=12500000000ULL;
    uint32_t nominal_mtu=1128;
    uint64_t bandwidth_delay_product=150000;
    uint64_t initial_maximum_window=225000;
    uint64_t target_queue_delay_ns=12000;
    double gamma=0.8;
    double proportional_gain_per_ns=0.376;
    double fair_increase_bytes=5640;
    double fast_increase_scale=0.25;
    double minimum_decrease_factor=0.5;
    double additive_increase_bytes=169.2;
    uint64_t quick_adapt_threshold_ns=48000;
    uint64_t adjustment_byte_threshold=9024;
    uint64_t adjustment_period_ns=12000;
    unsigned quick_adapt_gate_shift=3;
    bool disable_quick_adapt=false;
    // §3.6.13.6 leaves "delay ~= 0" implementation-specific. One service-time
    // quantum is our explicit near-zero tolerance, rather than a hidden epsilon.
    uint64_t fast_increase_delay_tolerance_ns=128;

    static NsccConfig for_link(uint64_t base_rtt_ns,uint64_t sender_rate,
                               uint64_t receiver_rate,uint32_t mtu,bool trimming=false) {
        if (!base_rtt_ns || !sender_rate || !receiver_rate || !mtu)
            throw std::invalid_argument("NSCC requires positive RTT, link rates and MTU");
        NsccConfig result;
        result.configured_base_rtt_ns=base_rtt_ns;
        result.sender_bytes_per_second=sender_rate;
        result.receiver_bytes_per_second=receiver_rate;
        result.nominal_mtu=mtu;
        const double bandwidth_delay_product=std::min(sender_rate,receiver_rate)*(base_rtt_ns/1e9);
        if (!std::isfinite(bandwidth_delay_product) || bandwidth_delay_product>double(INT64_MAX)/2)
            throw std::invalid_argument("NSCC bandwidth-delay product is too large");
        result.bandwidth_delay_product=static_cast<uint64_t>(bandwidth_delay_product);
        result.initial_maximum_window=std::max<uint64_t>(mtu,static_cast<uint64_t>(1.5*bandwidth_delay_product));
        result.target_queue_delay_ns=trimming?std::max<uint64_t>(1,base_rtt_ns*0.75):base_rtt_ns;
        const double scaling_a=bandwidth_delay_product/150000.0;
        const double scaling_b=result.target_queue_delay_ns/12000.0;
        result.proportional_gain_per_ns=4*scaling_a*scaling_b*mtu/result.target_queue_delay_ns;
        result.fair_increase_bytes=5*mtu*scaling_a;
        result.fast_increase_scale=0.25*scaling_a;
        result.additive_increase_bytes=0.15*mtu*scaling_a;
        if (!trimming && base_rtt_ns>UINT64_MAX/4)
            throw std::invalid_argument("NSCC quick-adapt threshold overflows nanoseconds");
        result.quick_adapt_threshold_ns=trimming?UINT64_MAX:4*base_rtt_ns;
        result.adjustment_byte_threshold=8*uint64_t{mtu};
        result.adjustment_period_ns=base_rtt_ns;
        result.validate();
        return result;
    }

    void validate() const {
        const auto nonnegative=[](double value) { return std::isfinite(value) && value>=0; };
        if (!configured_base_rtt_ns || !sender_bytes_per_second || !receiver_bytes_per_second || !nominal_mtu ||
            initial_maximum_window<nominal_mtu || initial_maximum_window>uint64_t{INT64_MAX}/2 ||
            !target_queue_delay_ns || !adjustment_period_ns || quick_adapt_gate_shift>=63 ||
            sender_bytes_per_second*(configured_base_rtt_ns/1e9)>double(INT64_MAX)/3 ||
            !nonnegative(gamma) || gamma>1 || !nonnegative(proportional_gain_per_ns) ||
            !nonnegative(fair_increase_bytes) || !nonnegative(fast_increase_scale) ||
            !nonnegative(minimum_decrease_factor) || minimum_decrease_factor>1 || !nonnegative(additive_increase_bytes))
            throw std::invalid_argument("invalid NSCC configuration");
    }
};

struct NsccTransmitSample {
    uint64_t transmit_time_ns=0;
    uint64_t retransmissions=0; // Karn's rule must not see zero again after counter wrap.
};
struct NsccAck {
    uint64_t newly_received_bytes=0;
    bool congestion_marked=false;
    std::optional<NsccTransmitSample> packet;
    uint16_t service_time_quanta=0; // 128 ns; zero invalid/ignored, 0xffff saturated.
    bool retransmit_flag=false;
    uint8_t receiver_window_penalty=0; // Seven-bit Rcv_Cwnd_Pend.
    bool restore_window=false;
    std::optional<uint64_t> first_bit_arrival_ns; // Separate from the later protocol-progress time.
};
enum class NsccNackReason { Other, Trimmed, TrimmedLastHop };

struct NsccState {
    uint64_t congestion_window=0;
    int64_t inflight_bytes=0; // MUST NOT clamp: ACK byte quantization can make this negative.
    uint64_t saved_window=0;
    uint64_t base_rtt_ns=0,maximum_window=0;
    uint64_t achieved_bytes=0,received_bytes=0,fast_increase_bytes=0;
    bool quick_adapt_triggered=false;
    uint64_t quick_adapt_end_ns=0,bytes_to_ignore=0,bytes_ignored=0;
    double increase_accumulator=0;
    uint64_t last_adjustment_ns=0,last_decrease_ns=0;
    bool fast_increase_mode=false;
};

// Pure congestion law: callers inject event time and perform per-packet/PDC
// deduplication. This class neither implements transport reliability nor owns a
// scheduler. Its byte accounting is §3.6.13.5, not a packet-count AIMD substitute.
class NsccController {
public:
    explicit NsccController(NsccConfig config={},uint64_t now_ns=0):config_(config),last_event_ns_(now_ns) {
        config_.validate();
        state_.congestion_window=state_.maximum_window=config_.initial_maximum_window;
        state_.base_rtt_ns=config_.configured_base_rtt_ns;
        state_.last_adjustment_ns=state_.last_decrease_ns=now_ns;
    }
    const NsccConfig& config() const { return config_; }
    const NsccState& state() const { return state_; }
    bool can_send() const {
        return state_.inflight_bytes<=static_cast<int64_t>(state_.congestion_window)-config_.nominal_mtu;
    }
    bool request_ack(uint64_t acknowledgment_trigger_bytes) const {
        return !can_send() || state_.congestion_window<acknowledgment_trigger_bytes;
    }
    void on_send(uint32_t nominal_packet_size,uint64_t now_ns) {
        advance(now_ns);
        if (state_.inflight_bytes>INT64_MAX-nominal_packet_size) throw std::overflow_error("NSCC inflight overflow");
        state_.inflight_bytes+=nominal_packet_size;
    }
    // A closed PDC contributes no live traffic to a shared CCC. Remove its
    // signed accounting residue without treating local retirement as ECN/loss.
    void retire_inflight(int64_t contribution,uint64_t now_ns) {
        advance(now_ns);
        if ((contribution>0 && state_.inflight_bytes<INT64_MIN+contribution) ||
            (contribution<0 && state_.inflight_bytes>INT64_MAX+contribution))
            throw std::overflow_error("NSCC retirement accounting overflow");
        state_.inflight_bytes-=contribution;
    }
    void on_ack(const NsccAck& ack,uint64_t now_ns) {
        advance(now_ns);
        if (ack.receiver_window_penalty>127) throw std::invalid_argument("NSCC receiver penalty exceeds seven bits");
        subtract_inflight(ack.newly_received_bytes);
        state_.bytes_ignored+=ack.newly_received_bytes;
        state_.received_bytes+=ack.newly_received_bytes;
        state_.achieved_bytes+=ack.newly_received_bytes;
        const bool receiver_limited=apply_receiver_penalty(ack);
        const auto arrival=std::min(now_ns,ack.first_bit_arrival_ns.value_or(now_ns));
        const auto rtt=rtt_sample(ack.packet,arrival,ack.service_time_quanta,ack.retransmit_flag);
        if (!rtt) return; // Byte accounting still applies when Karn's ambiguity rule rejects RTT.
        update_base_rtt(*rtt);
        const auto delay=*rtt-state_.base_rtt_ns;
        add_delay(now_ns,delay);
        if (quick_adapt(now_ns,false,ack.congestion_marked,delay)) return;
        if (!ack.congestion_marked && !receiver_limited) {
            if (delay>=config_.target_queue_delay_ns)
                state_.increase_accumulator+=config_.fair_increase_bytes*ack.newly_received_bytes;
            else proportional_increase(ack.newly_received_bytes,delay);
        } else if (ack.congestion_marked && delay>=config_.target_queue_delay_ns)
            multiplicative_decrease(now_ns);
        if (now_ns-state_.last_adjustment_ns>=config_.adjustment_period_ns ||
            state_.received_bytes>config_.adjustment_byte_threshold) fulfill_adjustment(now_ns);
    }
    void on_inferred_loss(uint32_t nominal_packet_size,uint64_t now_ns) {
        advance(now_ns);
        state_.congestion_window=subtract_window(nominal_packet_size);
        state_.bytes_ignored+=nominal_packet_size;
        subtract_inflight(nominal_packet_size);
    }
    void on_nack(uint32_t nominal_packet_size,const std::optional<NsccTransmitSample>& packet,
                 bool retransmit_flag,NsccNackReason reason,bool receiver_congestion_control,uint64_t now_ns) {
        advance(now_ns);
        subtract_inflight(nominal_packet_size);
        if (const auto rtt=rtt_sample(packet,now_ns,0,retransmit_flag)) update_base_rtt(*rtt);
        if (reason==NsccNackReason::Other) return;
        add_delay(now_ns,config_.configured_base_rtt_ns);
        state_.bytes_ignored+=nominal_packet_size;
        if (reason==NsccNackReason::TrimmedLastHop && receiver_congestion_control) return;
        state_.quick_adapt_triggered=true;
        if (!quick_adapt(now_ns,true,true,0)) state_.congestion_window=subtract_window(nominal_packet_size);
    }
private:
    NsccConfig config_;
    NsccState state_;
    uint64_t last_event_ns_;
    std::deque<std::pair<uint64_t,uint64_t>> delay_samples_;

    void advance(uint64_t now_ns) {
        if (now_ns<last_event_ns_) throw std::invalid_argument("NSCC event time moved backwards");
        last_event_ns_=now_ns;
    }
    void subtract_inflight(uint64_t bytes) {
        if (bytes>uint64_t{INT64_MAX} || state_.inflight_bytes<INT64_MIN+static_cast<int64_t>(bytes))
            throw std::overflow_error("NSCC inflight underflow");
        state_.inflight_bytes-=static_cast<int64_t>(bytes);
    }
    uint64_t subtract_window(uint64_t bytes) const {
        return bytes>=state_.congestion_window?config_.nominal_mtu:
            std::max<uint64_t>(config_.nominal_mtu,state_.congestion_window-bytes);
    }
    static std::optional<uint64_t> rtt_sample(const std::optional<NsccTransmitSample>& packet,uint64_t now_ns,
                                              uint16_t service_time,bool retransmit_flag) {
        if (!packet || service_time==0xffff || packet->transmit_time_ns>now_ns) return {};
        // §3.6.13.6 permits one retransmission only when the ACK identifies it.
        if (!((packet->retransmissions==0 && !retransmit_flag) || (packet->retransmissions==1 && retransmit_flag))) return {};
        const auto elapsed=now_ns-packet->transmit_time_ns;
        const uint64_t service_ns=uint64_t{service_time}*128;
        if (elapsed<=service_ns) return {};
        return elapsed-service_ns;
    }
    void update_base_rtt(uint64_t sample) {
        if (sample>=state_.base_rtt_ns) return;
        state_.base_rtt_ns=sample;
        const double maximum=1.5*config_.sender_bytes_per_second*(sample/1e9);
        // A usable window must hold one MTU even for a sub-MTU link BDP.
        state_.maximum_window=std::max<uint64_t>(config_.nominal_mtu,static_cast<uint64_t>(maximum));
    }
    bool apply_receiver_penalty(const NsccAck& ack) {
        if (ack.receiver_window_penalty) {
            if (!state_.saved_window) state_.saved_window=state_.congestion_window;
            const auto decrease=static_cast<uint64_t>(ack.receiver_window_penalty*(ack.newly_received_bytes/128.0));
            const auto capped=state_.inflight_bytes>0?std::min<uint64_t>(state_.congestion_window,state_.inflight_bytes):0;
            state_.congestion_window=decrease>=capped?config_.nominal_mtu:
                std::max<uint64_t>(config_.nominal_mtu,capped-decrease);
        } else if (ack.restore_window && state_.saved_window) {
            state_.congestion_window=state_.saved_window;
            state_.saved_window=0;
        }
        return ack.receiver_window_penalty!=0;
    }
    void discard_old_delays(uint64_t now_ns) {
        while (!delay_samples_.empty() && now_ns-delay_samples_.front().first>state_.base_rtt_ns)
            delay_samples_.pop_front();
    }
    void add_delay(uint64_t now_ns,uint64_t delay) {
        discard_old_delays(now_ns);
        delay_samples_.emplace_back(now_ns,delay);
    }
    double average_delay(uint64_t now_ns) {
        // §3.6.13.6 permits an implementation-defined mean. Use the exact
        // arithmetic mean of samples in the last measured base RTT.
        discard_old_delays(now_ns);
        double total=0;
        for (const auto& sample:delay_samples_) total+=sample.second;
        return delay_samples_.empty()?0:total/delay_samples_.size();
    }
    void proportional_increase(uint64_t bytes,uint64_t delay) {
        if (delay<=config_.fast_increase_delay_tolerance_ns) {
            state_.fast_increase_bytes+=bytes;
            if (state_.fast_increase_bytes>state_.congestion_window || state_.fast_increase_mode) {
                state_.congestion_window=static_cast<uint64_t>(std::min<double>(state_.maximum_window,
                    state_.congestion_window+bytes*config_.fast_increase_scale));
                state_.fast_increase_mode=true;
                return;
            }
        } else state_.fast_increase_bytes=0;
        state_.fast_increase_mode=false;
        state_.increase_accumulator+=config_.proportional_gain_per_ns*bytes*(config_.target_queue_delay_ns-delay);
    }
    void multiplicative_decrease(uint64_t now_ns) {
        state_.fast_increase_mode=false;
        state_.fast_increase_bytes=0;
        const auto average=average_delay(now_ns);
        if (average>config_.target_queue_delay_ns && now_ns-state_.last_decrease_ns>state_.base_rtt_ns) {
            const auto factor=std::max(1-config_.gamma*(average-config_.target_queue_delay_ns)/average,
                                       config_.minimum_decrease_factor);
            state_.congestion_window=std::max<uint64_t>(config_.nominal_mtu,state_.congestion_window*factor);
            state_.last_decrease_ns=now_ns;
        }
    }
    void fulfill_adjustment(uint64_t now_ns) {
        double increased=state_.congestion_window+state_.increase_accumulator/state_.congestion_window;
        if (now_ns-state_.last_adjustment_ns>=config_.adjustment_period_ns) {
            state_.last_adjustment_ns=now_ns;
            increased+=config_.additive_increase_bytes;
        }
        state_.congestion_window=static_cast<uint64_t>(std::min<double>(state_.maximum_window,increased));
        state_.increase_accumulator=0;
        state_.received_bytes=0;
    }
    bool quick_adapt(uint64_t now_ns,bool loss,bool marked,uint64_t delay) {
        if (config_.disable_quick_adapt) return false;
        bool adapted_or_ignored=false;
        if (state_.bytes_ignored<state_.bytes_to_ignore && marked) adapted_or_ignored=true;
        else if (now_ns>=state_.quick_adapt_end_ns) {
            if (state_.quick_adapt_end_ns && (state_.quick_adapt_triggered || loss || delay>config_.quick_adapt_threshold_ns) &&
                state_.achieved_bytes<(state_.maximum_window>>config_.quick_adapt_gate_shift)) {
                state_.congestion_window=std::max<uint64_t>(config_.nominal_mtu,state_.achieved_bytes);
                state_.bytes_to_ignore=state_.inflight_bytes>0?static_cast<uint64_t>(state_.inflight_bytes):0;
                state_.bytes_ignored=0;
                state_.quick_adapt_triggered=false;
                adapted_or_ignored=true;
            }
            state_.achieved_bytes=0;
            if (state_.base_rtt_ns>UINT64_MAX-now_ns || config_.target_queue_delay_ns>UINT64_MAX-now_ns-state_.base_rtt_ns)
                throw std::overflow_error("NSCC quick-adapt time overflow");
            state_.quick_adapt_end_ns=now_ns+state_.base_rtt_ns+config_.target_queue_delay_ns;
        }
        if (adapted_or_ignored) { state_.increase_accumulator=0; state_.received_bytes=0; }
        return adapted_or_ignored;
    }
};

// §3.6.10.3: the forward half of the 24-bit sequence space distinguishes
// progress (including wrap) from a duplicate or reordered ACK counter.
class ReceivedByteCounter {
public:
    uint64_t acknowledge(uint32_t encoded_units) {
        if (encoded_units>0xffffff) throw std::invalid_argument("NSCC byte counter exceeds 24 bits");
        const uint32_t distance=(encoded_units-previous_units_)&0xffffff;
        if (!distance || distance>=0x800000) return 0;
        previous_units_=encoded_units;
        return uint64_t{distance}<<8;
    }
    static uint32_t encode(uint64_t accepted_bytes) {
        return static_cast<uint32_t>((accepted_bytes/256+(accepted_bytes%256!=0))&0xffffff);
    }
private:
    uint32_t previous_units_=0;
};
} // namespace UET::CMS
