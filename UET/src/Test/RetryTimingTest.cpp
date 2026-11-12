#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

PDS_PDC_req noop_request() {
    PDS_PDC_req request{}; request.next_hdr=UET_HDR_REQUEST_STD; request.delivery_mode=RUD;
    request.som=request.eom=true; request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.som=header.eom=header.dc=1; header.opcode=1; header.msg_id=1;
    return request;
}
PDStoNET_pkt negative_acknowledgment(PDS_Nack_Codes code,uint16_t peer=MAX_PDC) {
    PDStoNET_pkt packet{}; packet.PDS_type=nack_header;
    auto& header=packet.PDS_header.nack_header;
    header.type=NACK; header.nack_code=code; header.spdcid=peer; header.dpdcid=1; header.nack_psn=1000;
    return packet;
}
void exact_timer_boundaries() {
    EventLoop loop; Services services{loop,loop,[]{}}; std::vector<uint32_t> expired;
    RTOTimer timer([&](uint32_t sequence) { expired.push_back(sequence); },&services);
    CHECK(timer.startTimerNanoseconds(1,128));
    CHECK(timer.getTimerInfo(1).duration_ns==128 && timer.getTimerInfo(1).rto==1);
    loop.run_until(127); CHECK(expired.empty());
    loop.run_until(128); CHECK(expired==std::vector<uint32_t>{1});
    CHECK(timer.startTimerNanoseconds(2,0)); CHECK(expired.size()==1);
    loop.run_until(128); CHECK(expired==std::vector<uint32_t>({1,2}));
    CHECK(timer.startTimerNanoseconds(3,kMaximumInitialRtoNs));
    CHECK(timer.getTimerInfo(3).duration_ns==8000000000ULL);
    CHECK(timer.updateNanoseconds(3,129));
    loop.run_until(256); CHECK(expired.size()==2);
    loop.run_until(257); CHECK(expired.back()==3);
    CHECK(timer.startTimerNanoseconds(4,kMaximumInitialRtoNs,1));
    CHECK(timer.getTimerInfo(4).duration_ns==16000000000ULL); // Eight-second initial RTO doubles to sixteen.
    check_throws<std::overflow_error>([&] { timer.startTimerNanoseconds(4,128,UINT16_MAX); });
    CHECK(timer.getTimerInfo(4).duration_ns==16000000000ULL && timer.getActiveTimerCount()==1);
    timer.clearAllTimers(); CHECK(loop.pending()==0);
    CHECK(retransmission_timeout_ns(UINT64_MAX,UINT16_MAX)==kMaximumBackoffNs);
    CHECK(retransmission_timeout_ns(0,UINT16_MAX)==0);
}

void nack_keeps_the_last_timeout(bool actual_mac) {
    EventLoop loop; Services services{loop,loop,[]{}};
    services.rto_ns=128; services.actual_transmit_notifications=actual_mac;
    I_PDC sender(&services); CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    auto request=noop_request(); sender.sesTxReq(&request);
    const auto start_current_attempt=[&] {
        if (actual_mac && sender.tx_pkt_map.at(1000).awaiting_transmission)
            CHECK(sender.notifyTransmit({*sender.tx_pkt_q.back().transmit_identity,loop.now(),TransmitOutcome::Started}));
    };
    const auto process_nack=[&](PDStoNET_pkt& packet) { sender.rxNack(&packet); loop.run_until(loop.now()); sender.openChk(); };
    start_current_attempt();
    loop.run_until(32);
    auto nack=negative_acknowledgment(UET_TRIMMED); process_nack(nack);
    if (actual_mac) CHECK(sender.rto_timer_.getActiveTimerCount()==0);
    start_current_attempt();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==1 && sender.tx_pkt_map.at(1000).timeout_retry_count==0);
    CHECK(sender.rto_timer_.getTimerInfo(1000).duration_ns==128);
    loop.run_until(159); CHECK(sender.rto_pkt_q.empty());
    loop.run_until(160); CHECK(sender.rto_pkt_q.size()==1); sender.rto_pkt_q.pop(); sender.txRto(1000);
    start_current_attempt();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==2 && sender.tx_pkt_map.at(1000).timeout_retry_count==1);
    CHECK(sender.rto_timer_.getTimerInfo(1000).duration_ns==256);
    loop.run_until(200); process_nack(nack); start_current_attempt();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==3 && sender.tx_pkt_map.at(1000).timeout_retry_count==1);
    CHECK(sender.rto_timer_.getTimerInfo(1000).duration_ns==256);
    loop.run_until(455); CHECK(sender.rto_pkt_q.empty());
    loop.run_until(456); CHECK(sender.rto_pkt_q.size()==1); sender.rto_pkt_q.pop(); sender.txRto(1000);
    start_current_attempt();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==4 && sender.tx_pkt_map.at(1000).timeout_retry_count==2);
    CHECK(sender.rto_timer_.getTimerInfo(1000).duration_ns==512);
    process_nack(nack); start_current_attempt();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==5 && sender.tx_pkt_map.at(1000).timeout_retry_count==2);
    process_nack(nack); CHECK(sender.close_error); // Common limit still counts NACKs, §3.5.12.7.
    sender.freePDC(); CHECK(loop.pending()==0);
}

void deferred_nack_retains_its_cause() {
    EventLoop loop; Services services{loop,loop,[]{}}; services.rto_ns=128;
    services.nack_retransmission_delays_ns[1]=64;
    I_PDC sender(&services); CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    auto request=noop_request(); sender.sesTxReq(&request);
    auto nack=negative_acknowledgment(UET_NO_PDC_AVAIL,0); sender.rxNack(&nack);
    CHECK(sender.rto_timer_.getActiveTimerCount()==0 && sender.pause_pdc);
    loop.run_until(63); CHECK(sender.tx_pkt_map.at(1000).retry_cnt==0);
    loop.run_until(64); sender.openChk();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==1 && sender.tx_pkt_map.at(1000).timeout_retry_count==0);
    CHECK(sender.rto_timer_.getTimerInfo(1000).duration_ns==128);
    sender.freePDC(); CHECK(loop.pending()==0);

    UET::CMS::NsccConfig config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,104);
    config.initial_maximum_window=104;
    UET::CMS::NsccEngine congestion(config,loop,[]{},{});
    services.congestion_control=&congestion;
    CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC; sender.sesTxReq(&request);
    // A second RUD PDC occupies the shared congestion window. The NACK retry
    // waits for CMS without becoming a timeout retry when it is later admitted.
    const UET::CMS::Connection competing{0,8,2000,false};
    auto competing_packet=sender.tx_pkt_buffer.at(1000); congestion.transmitted(competing,competing_packet);
    nack=negative_acknowledgment(UET_TRIMMED); sender.rxNack(&nack);
    loop.run_until(loop.now()); sender.openChk();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==0 && sender.rto_timer_.getActiveTimerCount()==0);
    congestion.closed(competing); sender.openChk();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==1 && sender.tx_pkt_map.at(1000).timeout_retry_count==0);
    CHECK(sender.rto_timer_.getTimerInfo(1000).duration_ns==128);
    sender.freePDC(); CHECK(loop.pending()==0);
}

void configuration_and_zero_timeout_failure() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1); fabric.add_host(2); fabric.add_link(1,2,{});
    PdsHost host(1,loop,trace,port);
    host.configure_retransmission_timeout(0); CHECK(host.services().rto_ns==0);
    host.configure_retransmission_timeout(128); CHECK(host.services().rto_ns==128);
    host.configure_retransmission_timeout(kMaximumInitialRtoNs);
    check_throws<std::invalid_argument>([&] { host.configure_retransmission_timeout(kMaximumInitialRtoNs+1); });
    host.close(); CHECK(loop.pending()==0);
    Services services{loop,loop,[]{}}; services.rto_ns=0;
    I_PDC sender(&services); CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    auto request=noop_request(); sender.sesTxReq(&request);
    for (size_t retry=0;retry<=Max_RTO_Retx_Cnt;++retry) {
        loop.run_until(loop.now()); CHECK(sender.rto_pkt_q.size()==1); sender.rto_pkt_q.pop(); sender.txRto(1000);
    }
    CHECK(sender.close_error && loop.pending()==0); // Zero RTO is finite under the configured finite retry limit.
    sender.freePDC();
}

void probe_uses_nanosecond_timeout() {
    EventLoop loop; Services services{loop,loop,[]{}}; services.rto_ns=128;
    I_PDC sender(&services); CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    sender.tx_cur_psn=1001; sender.clear_psn=1000;
    CHECK(sender.requestProbe(1000)); CHECK(sender.tx_pkt_q.size()==1);
    loop.run_until(127); sender.openChk(); CHECK(sender.tx_pkt_q.size()==1);
    loop.run_until(128); sender.openChk(); CHECK(sender.tx_pkt_q.size()==2);
    CHECK(sender.tx_pkt_q.back().PDS_header.RUOD_cp_header.flags.retx);
    CHECK(sender.tx_pkt_map.empty() && sender.tx_cur_psn==1001);
    sender.freePDC(); CHECK(loop.pending()==0);
}
int main() {
    try {
        exact_timer_boundaries(); nack_keeps_the_last_timeout(false); nack_keeps_the_last_timeout(true);
        deferred_nack_retains_its_cause(); configuration_and_zero_timeout_failure(); probe_uses_nanosecond_timeout();
        std::cout<<"PASS nanosecond RTO boundaries, NACK/RTO backoff distinction, MAC and deferred recovery\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
