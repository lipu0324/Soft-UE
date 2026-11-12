#include "Check.hpp"
#include "../CMS/Nscc.hpp"
#include <iostream>
using namespace UET::CMS;

NsccConfig controlled_config() {
    auto config=NsccConfig::for_link(1000,1000000000,1000000000,1000);
    config.initial_maximum_window=10000;
    config.proportional_gain_per_ns=1;
    config.fair_increase_bytes=5000;
    config.additive_increase_bytes=0;
    config.disable_quick_adapt=true;
    return config;
}

void byte_clock_and_gate() {
    auto config=controlled_config(); config.initial_maximum_window=3000;
    NsccController controller(config);
    CHECK(controller.can_send());
    controller.on_send(1000,0); controller.on_send(1000,0); controller.on_send(1000,0);
    CHECK(!controller.can_send() && controller.request_ack(1));
    NsccAck ack; ack.newly_received_bytes=3072; // ceil(3000/256)*256, not three per-packet roundings.
    controller.on_ack(ack,1000);
    CHECK(controller.state().inflight_bytes==-72 && controller.can_send());
    CHECK(controller.request_ack(4000));
    CHECK(ReceivedByteCounter::encode(0)==0 && ReceivedByteCounter::encode(1)==1);
    CHECK(ReceivedByteCounter::encode(257)==2 && ReceivedByteCounter::encode(3000)==12);
    CHECK(ReceivedByteCounter::encode(uint64_t{0x1000000}*256)==0);
    CHECK(ReceivedByteCounter::encode(UINT64_MAX)==0); // No accepted_bytes+255 overflow.
    ReceivedByteCounter counter;
    CHECK(counter.acknowledge(0x7fffff)==uint64_t{0x7fffff}*256);
    CHECK(counter.acknowledge(0xfffffe)==uint64_t{0x7fffff}*256);
    CHECK(counter.acknowledge(1)==3*256); // Forward wrap.
    CHECK(counter.acknowledge(0xffffff)==0 && counter.acknowledge(1)==0); // Reordering/duplicate.
    CHECK(counter.acknowledge(2)==256);
    check_throws<std::invalid_argument>([&] { counter.acknowledge(0x1000000); });
}

void four_ecn_delay_cases() {
    const auto config=controlled_config();
    const auto run=[&](bool marked,uint64_t rtt) {
        NsccController controller(config);
        controller.on_send(1000,0);
        controller.on_inferred_loss(1000,0); // Window 9000, inflight zero.
        controller.on_send(1000,0);
        NsccAck ack; ack.newly_received_bytes=1000; ack.congestion_marked=marked;
        ack.packet=NsccTransmitSample{0,0};
        controller.on_ack(ack,rtt);
        return controller.state().congestion_window;
    };
    // These expected values follow the §3.6.13.6 equations independently:
    // proportional: 9000+1*1000*1000/9000; fair: 9000+5000*1000/9000;
    // marked/high-delay: 9000*(1-.8*(2000-1000)/2000).
    CHECK(run(false,1000)==9111);
    CHECK(run(false,3000)==9555);
    CHECK(run(true,1500)==9000);
    CHECK(run(true,3000)==5400);
    NsccController repeated(config);
    NsccAck marked; marked.packet=NsccTransmitSample{0,0}; marked.congestion_marked=true;
    repeated.on_ack(marked,3000); const auto reduced=repeated.state().congestion_window;
    marked.packet=NsccTransmitSample{1000,0}; repeated.on_ack(marked,4000);
    CHECK(repeated.state().congestion_window==reduced); // Strictly more than one base RTT between decreases.
}

void rtt_and_receiver_penalty() {
    auto config=controlled_config();
    NsccController timed(config);
    NsccAck sample; sample.packet=NsccTransmitSample{0,0}; sample.service_time_quanta=1;
    timed.on_ack(sample,1128); CHECK(timed.state().base_rtt_ns==1000);
    sample.packet=NsccTransmitSample{1000,0}; sample.service_time_quanta=0xffff;
    timed.on_ack(sample,1250); CHECK(timed.state().base_rtt_ns==1000); // Saturated processing time has no precise RTT.
    sample.service_time_quanta=0; sample.retransmit_flag=true;
    timed.on_ack(sample,1500); CHECK(timed.state().base_rtt_ns==1000); // ACK and transmit history disagree.
    sample.packet=NsccTransmitSample{1500,1}; timed.on_ack(sample,2000);
    CHECK(timed.state().base_rtt_ns==500 && timed.state().maximum_window==1000);
    sample.packet=NsccTransmitSample{2000,2}; timed.on_ack(sample,2100);
    CHECK(timed.state().base_rtt_ns==500); // More than one retransmission is ambiguous.
    NsccController limited(config);
    for (unsigned packet=0;packet<8;++packet) limited.on_send(1000,0);
    NsccAck penalty; penalty.newly_received_bytes=1024; penalty.receiver_window_penalty=64;
    limited.on_ack(penalty,1000);
    CHECK(limited.state().saved_window==10000 && limited.state().congestion_window==6464);
    NsccAck restore; restore.restore_window=true; limited.on_ack(restore,2000);
    CHECK(limited.state().congestion_window==10000 && limited.state().saved_window==0);
    check_throws<std::invalid_argument>([&] { limited.on_send(1000,1999); });
}

void loss_and_quick_adapt() {
    auto config=controlled_config(); config.disable_quick_adapt=false;
    NsccController controller(config);
    for (unsigned packet=0;packet<5;++packet) controller.on_send(1000,0);
    controller.on_nack(1000,{},false,NsccNackReason::Trimmed,false,100);
    CHECK(controller.state().congestion_window==9000 && controller.state().quick_adapt_triggered);
    // The first trim starts the observation interval. A later trim after its
    // base RTT+target delay sees zero goodput and adapts to one MTU.
    controller.on_nack(1000,{},false,NsccNackReason::Trimmed,false,2100);
    CHECK(controller.state().congestion_window==1000 && controller.state().bytes_to_ignore==3000);
    CHECK(!controller.state().quick_adapt_triggered && controller.state().inflight_bytes==3000);
    NsccAck queued; queued.newly_received_bytes=1024; queued.congestion_marked=true;
    queued.packet=NsccTransmitSample{100,0}; controller.on_ack(queued,3100);
    CHECK(controller.state().congestion_window==1000 && controller.state().increase_accumulator==0);
    NsccController receiver_managed(config);
    receiver_managed.on_send(1000,0);
    receiver_managed.on_nack(1000,{},false,NsccNackReason::TrimmedLastHop,true,100);
    CHECK(receiver_managed.state().congestion_window==10000 && receiver_managed.state().inflight_bytes==0);
    receiver_managed.on_send(1000,100);
    receiver_managed.on_nack(1000,{},false,NsccNackReason::Other,false,200);
    CHECK(receiver_managed.state().congestion_window==10000); // Resource NACK is not a congestion signal.
    for (unsigned loss=0;loss<20;++loss) receiver_managed.on_inferred_loss(1000,200);
    CHECK(receiver_managed.state().congestion_window==1000);
}

int main() {
    const auto defaults=NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1000);
    CHECK(defaults.bandwidth_delay_product==150000 && defaults.initial_maximum_window==225000);
    CHECK(defaults.proportional_gain_per_ns==1.0/3 && defaults.fair_increase_bytes==5000);
    const auto trimmed=NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1000,true);
    CHECK(trimmed.target_queue_delay_ns==9000 && trimmed.quick_adapt_threshold_ns==UINT64_MAX);
    check_throws<std::invalid_argument>([] { NsccConfig::for_link(0,1,1,1); });
    auto invalid=defaults; invalid.gamma=std::numeric_limits<double>::quiet_NaN();
    check_throws<std::invalid_argument>([&] { NsccController rejected(invalid); });
    byte_clock_and_gate(); four_ecn_delay_cases(); rtt_and_receiver_penalty(); loss_and_quick_adapt();
    std::cout<<"PASS NSCC equations, byte clock, signed window accounting, RTT validity and quick adaptation\n";
}
