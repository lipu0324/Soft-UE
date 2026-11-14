#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::NetworkLayer;
using namespace UET::SES;

class TimingPdc final : public I_PDC {
public:
    using I_PDC::I_PDC;
    Time syn_safety_deadline() const { return syn_safety_deadline_; }
};

// Unlike a loss injector, a timing-capable NIC must retain the hooks until
// transmission or local rejection. WouldBlock transfers no frame ownership.
class PausedNic final : public IPacketPort {
public:
    explicit PausedNic(IPacketPort& wire):wire_(wire) {}
    bool provides_transmit_timing() const override { return true; }
    SendResult try_send(const Frame& frame) override {
        ++attempts;
        return paused_?SendResult::WouldBlock:wire_.try_send(frame);
    }
    void set_receiver(Receiver callback) override { wire_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { writable_=std::move(callback); }
    void resume() { paused_=false; if (writable_) writable_(); }
    size_t attempts=0;
private:
    IPacketPort& wire_;
    Writable writable_;
    bool paused_=true;
};

void backpressure_and_local_link_failure() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PausedNic nic(forward);
    PdsHost source_host(1,loop,trace,nic),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2;
    source.submit(noop);
    loop.run_until(2*kMillisecond);
    CHECK(nic.attempts==1); // More than the base RTO passed, without NIC ownership or a timer.
    CHECK(std::none_of(trace.events().begin(),trace.events().end(),[](const auto& event) { return event.event=="mac_tx"; }));
    Completion completion{}; CHECK(!source.poll_completion(completion));
    nic.resume(); loop.run_until(3*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);

    // A routing rejection also has no transmit sample, but must arm recovery.
    // Bringing the link back permits the existing PDS retry to finish the work.
    fabric.set_link_up(1,2,false); source.submit(noop);
    loop.at(3*kMillisecond+500000,[&] { fabric.set_link_up(1,2,true); });
    loop.run_until(5*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(std::any_of(trace.events().begin(),trace.events().end(),[](const auto& event) { return event.event=="nic_rejected"; }));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
    nic.resume(); CHECK(loop.pending()==0); // Stale writable readiness cannot restart a closed host.

    EventLoop queue_loop; Trace queue_trace(queue_loop); Fabric queued(queue_loop,queue_trace,42);
    auto& port=queued.add_host(1); queued.add_host(2);
    LinkConfig slow; slow.rate_bps=800000; queued.add_link(1,2,slow);
    size_t started=0,rejected=0;
    Frame frame; frame.source=1; frame.destination=2; frame.bytes.assign(100,0);
    frame.transmission_event=[&](uint64_t,TransmitOutcome outcome) {
        if (outcome==TransmitOutcome::Started) ++started; else ++rejected;
    };
    CHECK(port.try_send(frame)==SendResult::Accepted); CHECK(port.try_send(frame)==SendResult::Accepted);
    CHECK(started==1 && rejected==0);
    queue_loop.run_until(100); queued.set_link_up(1,2,false);
    CHECK(started==1 && rejected==1); // In-service loss was sent; queued discard was never sent.
    queued.set_link_up(1,2,true); queue_loop.run();
    CHECK(started==1 && rejected==1 && queued.stats(1,2).dropped==2);
}

void first_bit_starts_data_and_probe_timers() {
    EventLoop loop; Services services{loop,loop,[]{}}; services.actual_transmit_notifications=true;
    TimingPdc source(&services); CHECK(source.initPDC(1)); source.state=ESTABLISHED; source.SYN=true; source.DPDCID=MAX_PDC;
    PDS_PDC_req request{}; request.next_hdr=UET_HDR_REQUEST_STD; request.delivery_mode=RUD;
    request.som=request.eom=true; request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header; header.som=header.eom=header.dc=1; header.opcode=1; header.msg_id=1;
    source.sesTxReq(&request);
    const auto identity=*source.tx_pkt_buffer.at(1000).transmit_identity;
    CHECK(identity.synchronizing);
    CHECK(source.rto_timer_.getActiveTimerCount()==0 && source.tx_pkt_map.at(1000).awaiting_transmission);
    loop.run_until(2*kMillisecond); CHECK(source.rto_pkt_q.empty());
    CHECK(source.notifyTransmit({identity,loop.now(),TransmitOutcome::Started}));
    CHECK(!source.notifyTransmit({identity,loop.now(),TransmitOutcome::Started})); // Duplicate NIC notification.
    CHECK(source.tx_pkt_map.at(1000).last_transmit_time==2*kMillisecond);
    CHECK(source.rto_timer_.getActiveTimerCount()==1);
    loop.run_until(3*kMillisecond); CHECK(source.rto_pkt_q.size()==1);
    source.rto_pkt_q.pop(); source.gen_cm=NONE; source.txRto(1000);
    CHECK(source.tx_pkt_map.at(1000).retry_cnt==1 && source.tx_pkt_map.at(1000).awaiting_transmission);
    CHECK(source.syn_safety_deadline()==67*kMillisecond); // Lost attempt left the NIC at 2 ms, not at submission.
    source.txRto(1000); CHECK(source.tx_pkt_map.at(1000).retry_cnt==1); // Waiting at NIC consumes no extra retry.
    CHECK(!source.notifyTransmit({identity,loop.now(),TransmitOutcome::Started})); // Old attempt.
    const auto retry_identity=*source.tx_pkt_q.back().transmit_identity;
    CHECK(source.notifyTransmit({retry_identity,loop.now(),TransmitOutcome::Rejected}));
    CHECK(!source.tx_pkt_map.at(1000).transmit_time_valid && source.rto_timer_.getActiveTimerCount()==1);
    loop.run_until(5*kMillisecond); CHECK(source.rto_pkt_q.size()==1); source.rto_pkt_q.pop();
    source.gen_cm=NONE; source.txRto(1000);
    CHECK(source.tx_pkt_map.at(1000).retry_cnt==2 && source.syn_safety_deadline()==67*kMillisecond);
    const auto second_retry=*source.tx_pkt_q.back().transmit_identity;
    CHECK(source.notifyTransmit({second_retry,loop.now(),TransmitOutcome::Started}));
    CHECK(source.syn_safety_deadline()==67*kMillisecond); // Sending another SYN is not yet evidence that it was lost.
    source.freePDC(); CHECK(loop.pending()==0);
    CHECK(source.initPDC(1)); source.state=ESTABLISHED; source.DPDCID=MAX_PDC; source.sesTxReq(&request);
    CHECK(!source.notifyTransmit({identity,loop.now(),TransmitOutcome::Started})); // Same ID and PSN, different incarnation.
    CHECK(source.rto_timer_.getActiveTimerCount()==0);
    source.freePDC(); CHECK(loop.pending()==0);

    CHECK(source.initPDC(1)); source.state=ESTABLISHED; source.DPDCID=MAX_PDC;
    source.tx_cur_psn=1001; source.clear_psn=1000; CHECK(source.requestProbe(1000));
    const auto probe_identity=*source.tx_pkt_q.front().transmit_identity;
    CHECK(probe_identity.kind==TransmitKind::Probe && loop.pending()==0);
    CHECK(source.notifyTransmit({probe_identity,loop.now(),TransmitOutcome::Started}));
    CHECK(loop.pending()==1 && source.tx_pkt_map.empty());
    source.freePDC(); CHECK(loop.pending()==0);
}

void service_stamp_preserves_the_actual_frame() {
    for (const bool ipv6:{false,true}) for (const bool udp:{false,true}) for (const bool crc:{false,true}) {
        PDStoNET_pkt packet{}; packet.PDS_type=RUOD_ack_header;
        auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
        acknowledgment.type=ACK_CC; acknowledgment.next_hdr=UET_HDR_NONE;
        acknowledgment.cack_psn=1000; packet.congestion_ack.received_byte_units=123;
        WireOptions options; options.ipv6=ipv6; options.udp=udp; options.native_ip_protocol=253; options.crc=crc; options.ecn=2;
        auto frame=UetWireCodec::encode(packet,options);
        if (udp) { const size_t start=14+(ipv6?40:20); frame[start+6]=0xbe; frame[start+7]=0xef; }
        CHECK(UetWireCodec::mark_ecn(frame));
        frame.insert(frame.end(),7,0xa5); // Ethernet padding lies outside the IP/CRC extent.
        const auto before=frame;
        CHECK(UetWireCodec::stamp_service_time(frame,1000,1,crc,253));
        const auto decoded=UetWireCodec::decode(frame.data(),frame.size(),crc,253);
        CHECK(decoded.packet.congestion_ack.service_time==8 && decoded.packet.congestion_ack.received_byte_units==123);
        CHECK(decoded.network.ecn==3 && frame.size()==before.size());
        const size_t transport=14+(ipv6?40:20),pds=transport+(udp?8:4),crc_end=before.size()-7;
        for (size_t byte=0;byte<frame.size();++byte)
            if (byte!=pds+24 && byte!=pds+25 && !(crc && byte>=crc_end-4 && byte<crc_end)) CHECK(frame[byte]==before[byte]);
        CHECK(UetWireCodec::stamp_service_time(frame,UINT64_MAX,0,crc,253));
        CHECK(UetWireCodec::decode(frame.data(),frame.size(),crc,253).packet.congestion_ack.service_time==0xffff);
        CHECK(UetWireCodec::stamp_service_time(frame,10,10,crc,253));
        CHECK(UetWireCodec::decode(frame.data(),frame.size(),crc,253).packet.congestion_ack.service_time==1);
        TrimmingOptions trimming; frame=UetWireCodec::encode(packet,options);
        CHECK(UetWireCodec::trim_packet(frame,trimming)); const auto trimmed=frame;
        CHECK(!UetWireCodec::stamp_service_time(frame,1000,0,crc,253) && frame==trimmed);
    }
}

void source_hooks_run_once_and_wire_loss_uses_capacity() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& first=fabric.add_host(1); fabric.add_host(2); fabric.add_switch(10);
    LinkConfig link; link.rate_bps=1000000000; link.delay_ns=100;
    fabric.add_link(1,10,link); fabric.add_link(10,2,link);
    size_t prepared=0,started=0,captured=0; Time departure=UINT64_MAX;
    fabric.set_link_capture([&](Time,uint32_t,uint32_t,const Frame&) { ++captured; });
    Frame frame; frame.source=1; frame.destination=2; frame.bytes.assign(100,0);
    frame.prepare_transmission=[&](uint64_t time,std::vector<uint8_t>&) { ++prepared; departure=time; };
    frame.transmission_event=[&](uint64_t,TransmitOutcome outcome) { CHECK(outcome==TransmitOutcome::Started); ++started; };
    CHECK(first.try_send(frame)==SendResult::Accepted); loop.run();
    CHECK(prepared==1 && started==1 && captured==2 && departure==0);

    EventLoop loss_loop; Trace loss_trace(loss_loop); Fabric lossy(loss_loop,loss_trace,42);
    auto& port=lossy.add_host(1); lossy.add_host(2);
    link.drop_ppm=1000000; lossy.add_link(1,2,link);
    size_t attempts=0; frame.destination=2; frame.prepare_transmission={};
    frame.transmission_event=[&](uint64_t,TransmitOutcome outcome) { CHECK(outcome==TransmitOutcome::Started); ++attempts; };
    CHECK(port.try_send(frame)==SendResult::Accepted); CHECK(port.try_send(frame)==SendResult::Accepted);
    CHECK(lossy.stats(1,2).queued_bytes==200 && attempts==1);
    loss_loop.run_until(799); CHECK(attempts==1);
    loss_loop.run(); CHECK(attempts==2 && lossy.stats(1,2).dropped==2 && lossy.stats(1,2).delivered==0);
}

void receiver_output_queue_is_service_not_network_delay() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    LinkConfig incoming,outgoing; outgoing.rate_bps=1000000000; outgoing.mtu=16384;
    fabric.add_link(1,2,incoming); fabric.add_link(2,1,outgoing);
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,125000000ULL,256);
    source_host.enable_nscc(config); target_host.enable_nscc(config);
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,16,7);
    uint16_t local_pdc=0; uint32_t start=0; uint16_t service=0; Time ack_departure=0;
    fabric.set_link_capture([&](Time time,uint32_t from,uint32_t,const Frame& frame) {
        try {
            const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),true,253).packet;
            if (packet.PDS_type==RUOD_req_header) { local_pdc=packet.PDS_header.RUOD_req_header.spdcid; start=packet.PDS_header.RUOD_req_header.psn; }
            if (from==2 && packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.type==ACK_CC) {
                service=packet.congestion_ack.service_time; ack_departure=time;
            }
        } catch (const std::invalid_argument&) { /* Synthetic background bytes are deliberately not UET. */ }
    });
    Frame background; background.source=2; background.destination=1; background.traffic_class=1; background.bytes.assign(12000,0);
    CHECK(reverse.try_send(background)==SendResult::Accepted);
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=region.key; write.payload.assign(16,0x5a);
    source.submit(write); loop.run_until(200000,10000);
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(ack_departure==96000 && service==(96000-1000+127)/128);
    const UET::CMS::Connection connection{2,local_pdc,start,true};
    const auto base_rtt=source_host.nscc()->state(connection).base_rtt_ns;
    CHECK(base_rtt>=1800 && base_rtt<=2200); // Output queue and ACK serialization are excluded.
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        first_bit_starts_data_and_probe_timers(); backpressure_and_local_link_failure(); service_stamp_preserves_the_actual_frame();
        source_hooks_run_once_and_wire_loss_uses_capacity(); receiver_output_queue_is_service_not_network_delay();
        std::cout<<"PASS actual MAC timestamps, queue-aware service/RTT, independent timers, incarnation safety and physical loss capacity\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
