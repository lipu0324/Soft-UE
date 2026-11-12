#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <set>
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

PDS_PDC_req request(pdc_mode mode=RUD,uint16_t message=1) {
    PDS_PDC_req packet{}; packet.next_hdr=UET_HDR_REQUEST_STD; packet.delivery_mode=mode;
    packet.som=packet.eom=true; packet.pkt.bth_type=Standard_Header;
    auto& semantic=packet.pkt.bth_header.Standard_Header;
    semantic.som=semantic.eom=semantic.dc=1; semantic.opcode=1; semantic.msg_id=message;
    return packet;
}
PDStoNET_pkt nack(uint8_t code,uint32_t sequence=1000,uint16_t peer=MAX_PDC) {
    PDStoNET_pkt packet{}; packet.PDS_type=nack_header;
    auto& header=packet.PDS_header.nack_header;
    header.type=NACK; header.next_hdr=UET_HDR_NONE; header.nack_code=static_cast<PDS_Nack_Codes>(code); header.nack_psn=sequence;
    header.spdcid=peer; header.dpdcid=1;
    header.payload=sequence; // An in-order dropped packet's Expected_PSN.
    return packet;
}
PDStoNET_pkt acknowledgment(bool semantic) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_ack_header;
    auto& header=packet.PDS_header.RUOD_ack_header;
    header.type=ACK; header.next_hdr=semantic?UET_HDR_RESPONSE:UET_HDR_NONE;
    header.cack_psn=1000; header.spdcid=MAX_PDC; header.dpdcid=1;
    if (semantic) {
        packet.SESpkt.bth_type=Semantic_Response_Header;
        auto& response=packet.SESpkt.bth_header.Semantic_Response_Header;
        response.opcode=0; response.return_code=1; response.message_id=1;
    }
    return packet;
}
void initialize(I_PDC& sender,pdc_mode mode=RUD,uint32_t first=1000,size_t count=1) {
    CHECK(sender.initPDC(1,first)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    for (size_t index=0;index<count;++index) { auto packet=request(mode,index+1); sender.sesTxReq(&packet); }
}
void classification_and_reserved_state() {
    const std::set<unsigned> closing{0x0e,0x0f,0x10,0x11,0x13,0x15,0x16,0x19,0xfe,0xff};
    for (unsigned code=0;code<256;++code) {
        const bool valid=(code>=1 && code<=0x1b && code!=3 && code!=0x0c) || code>=0xfd;
        const auto policy=UET::PDS::negative_acknowledgment_policy(code);
        CHECK(policy.has_value()==valid);
        if (!valid) continue;
        const auto expected=closing.count(code)?UET::PDS::NegativeAcknowledgmentAction::CloseConnection:
            code==0x17?UET::PDS::NegativeAcknowledgmentAction::NewStartSequence:
            UET::PDS::NegativeAcknowledgmentAction::Retransmit;
        CHECK(policy->action==expected && policy->delay_group<4);
    }
    EventLoop loop; Trace trace(loop); Services services{loop,loop,[]{}};
    UET::CMS::NsccEngine congestion({},loop,[]{},{},&trace); services.congestion_control=&congestion;
    I_PDC sender(&services); initialize(sender);
    const UET::CMS::Connection connection{0,1,1000,false};
    const auto inflight=congestion.state(connection).inflight_bytes;
    const auto window=congestion.state(connection).congestion_window;
    for (unsigned code=0;code<256;++code) {
        if (UET::PDS::negative_acknowledgment_policy(code)) continue;
        auto packet=nack(code); sender.rxNack(&packet);
        CHECK(sender.tx_pkt_map.at(1000).retry_cnt==0 && !sender.close_error && !sender.pause_pdc);
    }
    auto future=nack(1,1001); sender.rxNack(&future);
    CHECK(congestion.state(connection).inflight_bytes==inflight && congestion.state(connection).congestion_window==window);
    CHECK(std::none_of(trace.events().begin(),trace.events().end(),[](const auto& event) { return event.event=="nscc_nack"; }));
    CHECK(sender.rto_timer_.getActiveTimerCount()==1);
    sender.freePDC(); CHECK(loop.pending()==0);
}
void delayed_retry_and_duplicate(bool unbound) {
    EventLoop loop; Services services{loop,loop,[]{}}; services.rto_ns=1000;
    services.nack_retransmission_delays_ns[1]=256;
    I_PDC sender(&services); initialize(sender);
    auto packet=nack(unbound?UET_NO_PDC_AVAIL:UET_NO_PKT_BUFFER,1000,unbound?0:MAX_PDC);
    sender.rxNack(&packet); CHECK(sender.rto_timer_.getActiveTimerCount()==0);
    loop.run_until(128); sender.rxNack(&packet); // Must not move the original 256 ns deadline.
    loop.run_until(255); sender.openChk(); CHECK(sender.tx_pkt_map.at(1000).retry_cnt==0);
    loop.run_until(256); sender.openChk();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==1 && sender.tx_pkt_map.at(1000).timeout_retry_count==0);
    CHECK(sender.rto_timer_.getTimerInfo(1000).start_time_ns==256 && sender.rto_timer_.getTimerInfo(1000).duration_ns==1000);
    sender.freePDC(); CHECK(loop.pending()==0);
}
void acknowledgment_beats_delayed_retry(bool semantic) {
    EventLoop loop; Services services{loop,loop,[]{}}; services.rto_ns=1000;
    services.nack_retransmission_delays_ns[2]=200;
    I_PDC sender(&services); initialize(sender);
    auto packet=nack(UET_RCVD_SES_PROCG); sender.rxNack(&packet);
    loop.run_until(100); auto response=acknowledgment(semantic); sender.rxAck(&response);
    loop.run_until(200); sender.openChk();
    CHECK(sender.tx_pkt_q.size()==1); // No duplicate data was generated.
    if (semantic) CHECK(sender.tx_pkt_map.empty() && loop.pending()==0);
    else {
        CHECK(sender.tx_pkt_map.at(1000).delivery_confirmed && sender.tx_pkt_map.at(1000).retry_cnt==0);
        loop.run_until(1099); CHECK(sender.rto_pkt_q.empty());
        loop.run_until(1100); sender.openChk();
        CHECK(sender.tx_pkt_q.back().PDS_type==RUOD_cp_header && sender.tx_pkt_q.back().PDS_header.RUOD_cp_header.ctl_type==ACK_req);
        CHECK(sender.tx_pkt_map.at(1000).retry_cnt==1); // Missing semantics retain their own recovery.
    }
    sender.freePDC(); CHECK(loop.pending()==0);
}
void delayed_event_cannot_cross_reuse() {
    EventLoop loop; Services services{loop,loop,[]{}}; services.rto_ns=1000;
    services.nack_retransmission_delays_ns[2]=200;
    I_PDC sender(&services); initialize(sender);
    auto packet=nack(UET_RCVD_SES_PROCG); sender.rxNack(&packet); sender.freePDC(); CHECK(loop.pending()==0);
    initialize(sender); loop.run_until(200); sender.openChk();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==0 && sender.rto_timer_.getActiveTimerCount()==1);
    sender.freePDC(); CHECK(loop.pending()==0);
}
void delivery_mode_recovery(pdc_mode mode,uint8_t code,bool wrapping=false) {
    EventLoop loop; Services services{loop,loop,[]{}}; services.nack_retransmission_delays_ns.fill(0);
    I_PDC sender(&services); const uint32_t first=wrapping?UINT32_MAX-1:1000;
    initialize(sender,mode,first,3);
    CHECK(sender.mode==mode);
    auto packet=nack(code,first+1); sender.rxNack(&packet); loop.run_until(loop.now());
    for (size_t step=0;step<16 && sender.hasPendingWork();++step) sender.openChk();
    CHECK(!sender.hasPendingWork());
    CHECK(sender.tx_pkt_map.at(first).retry_cnt==0);
    CHECK(sender.tx_pkt_map.at(first+1).retry_cnt==1 && sender.tx_pkt_map.at(first+1).timeout_retry_count==0);
    if (sender.tx_pkt_map.at(first+2).retry_cnt!=(mode==ROD?1:0))
        std::cerr<<"mode="<<mode<<" code="<<unsigned(code)<<" first="<<first<<" final retries="<<sender.tx_pkt_map.at(first+2).retry_cnt<<'\n';
    CHECK(sender.tx_pkt_map.at(first+2).retry_cnt==(mode==ROD?1:0));
    sender.freePDC(); CHECK(loop.pending()==0);
}
void reserved_wire_nack_cannot_bind_peer() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost host(1,loop,trace,forward); Endpoint source(1,host,loop,trace); source.memory().add_job(1);
    PDStoNET_pkt original{};
    fabric.set_capture([&](Time,const Frame& frame) {
        if (frame.source==1) {
            const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
            if (decoded.PDS_type==RUOD_req_header) original=decoded;
        }
    });
    Operation operation; operation.type=OperationType::Noop; operation.peer=2; source.submit(operation); loop.run_until(0);
    CHECK(original.PDS_type==RUOD_req_header);
    const auto& request_header=original.PDS_header.RUOD_req_header;
    auto invalid=nack(0x03,request_header.psn,900); invalid.PDS_header.nack_header.dpdcid=request_header.spdcid;
    UET::NetworkLayer::WireOptions wire; wire.source.ip[3]=2; wire.destination.ip[3]=1;
    Frame frame; frame.source=2; frame.destination=1; frame.bytes=UetWireCodec::encode(invalid,wire);
    CHECK(reverse.try_send(frame)==SendResult::Accepted); loop.run_until(5000);
    auto valid=acknowledgment(true); valid.PDS_header.RUOD_ack_header.cack_psn=request_header.psn;
    valid.PDS_header.RUOD_ack_header.dpdcid=request_header.spdcid;
    auto& response=valid.SESpkt.bth_header.Semantic_Response_Header;
    response.job_id=original.SESpkt.bth_header.Standard_Header.job_id;
    response.message_id=original.SESpkt.bth_header.Standard_Header.msg_id;
    frame.bytes=UetWireCodec::encode(valid,wire); CHECK(reverse.try_send(frame)==SendResult::Accepted);
    loop.run_until(10000);
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    source.close(); host.close(); CHECK(loop.pending()==0);
}
void delay_configuration_boundaries() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1); fabric.add_host(2); fabric.add_link(1,2,{});
    PdsHost host(1,loop,trace,port);
    host.configure_negative_acknowledgment_delays({0,128,kMaximumInitialRtoNs,0});
    CHECK(host.services().nack_retransmission_delays_ns[1]==128);
    check_throws<std::invalid_argument>([&] { host.configure_negative_acknowledgment_delays({0,0,kMaximumInitialRtoNs+1,0}); });
    CHECK(host.open_connection(2)!=UINT16_MAX);
    check_throws<std::logic_error>([&] { host.configure_negative_acknowledgment_delays({0,0,0,0}); });
    host.close(); CHECK(loop.pending()==0);
}
void ordered_recovery_rounds() {
    UET::PDS::OrderedRecovery recovery;
    CHECK(!recovery.active());
    CHECK(recovery.observe(UINT32_MAX-1,false));
    CHECK(!recovery.observe(UINT32_MAX-1,false));
    CHECK(!recovery.observe(UINT32_MAX-2,false));
    CHECK(recovery.observe(UINT32_MAX-1,true)); // First RETX=1 opens one new round.
    CHECK(!recovery.observe(UINT32_MAX-1,true));
    CHECK(recovery.observe(0,true)); // A newer gap across wrap is a new loss.
    CHECK(!recovery.observe(UINT32_MAX,true));
    recovery.acknowledged(); CHECK(!recovery.active());
    CHECK(recovery.observe(0,false)); // An ACK ends the old episode.
}
void ordered_retries_preserve_sequence(bool wrapping) {
    EventLoop loop; Services services{loop,loop,[]{}}; services.nack_retransmission_delays_ns.fill(0);
    I_PDC sender(&services); const uint32_t first=wrapping?UINT32_MAX-1:1000;
    initialize(sender,ROD,first,3);
    while (!sender.tx_pkt_q.empty()) sender.tx_pkt_q.pop();
    auto packet=nack(UET_TRIMMED,first+2); packet.PDS_header.nack_header.payload=first;
    sender.rxNack(&packet); loop.run_until(0);
    for (size_t step=0;step<16 && sender.hasPendingWork();++step) sender.openChk();
    std::vector<uint32_t> actual;
    while (!sender.tx_pkt_q.empty()) {
        const auto& sent=sender.tx_pkt_q.front();
        if (sent.PDS_type==RUOD_req_header) actual.push_back(sent.PDS_header.RUOD_req_header.psn);
        sender.tx_pkt_q.pop();
    }
    CHECK(actual==std::vector<uint32_t>({first,first+1,first+2}));
    sender.freePDC(); CHECK(loop.pending()==0);
}
void acknowledged_unsent_loss_restores_accounting() {
    EventLoop loop; Trace trace(loop); Services services{loop,loop,[]{}};
    auto config=UET::CMS::NsccConfig{}; config.nominal_mtu=104; config.initial_maximum_window=4*104;
    UET::CMS::NsccEngine congestion(config,loop,[]{},{},&trace); services.congestion_control=&congestion;
    I_PDC sender(&services); initialize(sender,ROD,1000,4);
    const UET::CMS::Connection connection{0,1,1000,true};
    CHECK(congestion.state(connection).inflight_bytes==416);
    // Naming the last packet still begins recovery at Expected_PSN=1000.
    // The other originals may be accepted before their replacements leave.
    auto packet=nack(UET_TRIMMED,1003); packet.PDS_header.nack_header.payload=1000;
    sender.rxNack(&packet); loop.run_until(0);
    for (size_t step=0;step<16 && sender.hasPendingWork();++step) sender.openChk();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==1);
    CHECK(sender.tx_pkt_map.at(1001).retry_cnt==0);
    CHECK(sender.tx_pkt_map.at(1001).congestion_debit_waiting_for_retry);
    auto response=acknowledgment(false); response.PDS_header.RUOD_ack_header.type=ACK_CC;
    response.PDS_header.RUOD_ack_header.cack_psn=1003;
    response.congestion_ack.received_byte_units=2; // ceil(416 / 256).
    sender.rxAck(&response);
    CHECK(congestion.state(connection).inflight_bytes==416-512);
    for (const auto& metadata:sender.tx_pkt_map) CHECK(!metadata.second.congestion_debit_waiting_for_retry);
    const auto before=congestion.state(connection).inflight_bytes;
    sender.rxAck(&response); CHECK(congestion.state(connection).inflight_bytes==before);
    sender.freePDC(); CHECK(loop.pending()==0);
}
void ordered_recovery_blocks_new_data() {
    EventLoop loop; Services services{loop,loop,[]{}}; services.nack_retransmission_delays_ns.fill(0);
    I_PDC sender(&services); initialize(sender,ROD,1000,3);
    sender.tx_req_q.push(request(ROD,4));
    auto packet=nack(UET_TRIMMED); sender.rxNack(&packet); loop.run_until(0);
    const auto progress=[&] { for (size_t step=0;step<16 && sender.hasPendingWork();++step) sender.openChk(); };
    progress(); CHECK(sender.tx_req_q.size()==1 && sender.tx_pkt_map.at(1000).retry_cnt==1);
    sender.rxNack(&packet); loop.run_until(0); progress();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==1); // Same original-loss round.
    packet.PDS_header.nack_header.flags.retx=1;
    sender.rxNack(&packet); loop.run_until(0); progress();
    CHECK(sender.tx_pkt_map.at(1000).retry_cnt==2);
    sender.rxNack(&packet); loop.run_until(0); progress();
    CHECK(sender.tx_req_q.size()==1 && sender.tx_pkt_map.at(1000).retry_cnt==2);
    auto response=acknowledgment(true); sender.rxAck(&response); progress();
    CHECK(sender.tx_req_q.empty() && sender.tx_pkt_map.count(1003));
    // A delayed NACK naming the already confirmed packet cannot start an
    // empty recovery episode that blocks this connection indefinitely.
    auto receipt=acknowledgment(false); receipt.PDS_header.RUOD_ack_header.cack_psn=1001;
    sender.rxAck(&receipt);
    auto stale=nack(UET_TRIMMED,1001); sender.rxNack(&stale);
    sender.tx_req_q.push(request(ROD,5)); progress(); CHECK(sender.tx_req_q.empty());
    sender.freePDC(); CHECK(loop.pending()==0);
}
int main() {
    const char* phase="classification";
    try {
        classification_and_reserved_state();
        phase="bound delay"; delayed_retry_and_duplicate(false);
        phase="unbound delay"; delayed_retry_and_duplicate(true);
        phase="receipt cancels data"; acknowledgment_beats_delayed_retry(false);
        phase="semantic ACK cancels retry"; acknowledgment_beats_delayed_retry(true);
        phase="reuse"; delayed_event_cannot_cross_reuse();
        phase="delivery-mode recovery";
        for (const auto mode:{RUD,ROD}) for (const auto code:{UET_TRIMMED,UET_NO_PKT_BUFFER,UET_NO_RESOURCE,UET_RCVD_SES_PROCG,UET_NO_SES_SYNC_AVAIL})
            delivery_mode_recovery(mode,code);
        phase="wrap"; delivery_mode_recovery(ROD,UET_TRIMMED,true);
        phase="wire peer binding"; reserved_wire_nack_cannot_bind_peer();
        phase="delay configuration"; delay_configuration_boundaries();
        phase="ordered recovery rounds"; ordered_recovery_rounds();
        phase="ordered retry sequence"; ordered_retries_preserve_sequence(false); ordered_retries_preserve_sequence(true);
        phase="late delivery accounting"; acknowledged_unsent_loss_restores_accounting();
        phase="ordered new-data blocking"; ordered_recovery_blocks_new_data();
        std::cout<<"PASS NACK classification, exact delays, ACK cancellation, RUD/ROD recovery, wrap and peer binding\n";
    } catch (const std::exception& error) { std::cerr<<phase<<": "<<error.what()<<'\n'; return 1; }
}
