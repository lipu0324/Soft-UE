#include "Check.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

class ProbeTarget : public T_PDC {
public:
    using T_PDC::T_PDC;
    using PDC::receiveProbe;
    using PDC::completed_rx_psns_;
};

void destination_probe_bitmap(pdc_mode mode) {
    EventLoop loop; Services services{loop,loop,[]{}};
    ProbeTarget target(&services); CHECK(target.initPDC(MAX_PDC));
    target.mode=mode; target.state=ESTABLISHED; target.start_psn=1000;
    target.cack_psn=1003; target.rx_cur_psn=1006; target.rx_clear_psn=1003;
    target.completed_rx_psns_.insert(1006);
    target.tx_ack_buffer.emplace(1004,PDStoNET_pkt{}); // A guaranteed result awaiting Clear.
    // 1005 is still processing in SES and must not appear in the bitmap.
    PDStoNET_pkt probe{}; probe.PDS_type=RUOD_cp_header;
    auto& control=probe.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=Probe; control.flags.ar=1; control.probe_opaque=0xbeef;
    control.payload=1000; probe.wire_entropy=0xabcd; probe.network_ecn=3;
    const auto before=target.rx_cur_psn; target.receiveProbe(probe);
    CHECK(target.tx_pkt_q.size()==1);
    auto reply=target.tx_pkt_q.front(); target.tx_pkt_q.pop();
    const auto& acknowledgment=reply.PDS_header.RUOD_ack_header;
    CHECK(acknowledgment.type==ACK_CC && acknowledgment.flags.p && !acknowledgment.flags.req);
    CHECK(static_cast<uint16_t>(acknowledgment.ack_psn_off)==0xbeef && acknowledgment.cack_psn==1003);
    CHECK(reply.congestion_ack.sack_psn_offset==0 && reply.congestion_ack.sack_bitmap==0b1011);
    CHECK(reply.wire_entropy==0xabcd && acknowledgment.flags.m && !acknowledgment.flags.retx);
    CHECK(target.rx_cur_psn==before && target.cack_psn==1003 && target.rx_req_pkt_q.empty());
    control.payload=1008; target.receiveProbe(probe);
    CHECK(target.tx_pkt_q.front().congestion_ack.sack_psn_offset==5);
    CHECK(target.tx_pkt_q.front().congestion_ack.sack_bitmap==0); target.tx_pkt_q.pop();
    control.flags.ar=0; target.receiveProbe(probe); CHECK(target.tx_pkt_q.empty());
    target.freePDC(); CHECK(loop.pending()==0);
}

PDStoNET_pkt probe_ack(uint16_t opaque,uint32_t cumulative) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_ack_header;
    auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
    acknowledgment.type=ACK_CC; acknowledgment.next_hdr=UET_HDR_NONE; acknowledgment.flags.p=1;
    acknowledgment.cack_psn=cumulative; acknowledgment.ack_psn_off=static_cast<int16_t>(opaque);
    return packet;
}

void probe_opaque_never_acknowledges_a_packet(uint16_t opaque) {
    EventLoop loop; Services services{loop,loop,[]{}}; services.next_probe_opaque=opaque-1;
    I_PDC sender(&services); CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    sender.start_psn=sender.tx_cur_psn=UINT32_MAX-1; sender.clear_psn=UINT32_MAX-2;
    PDS_PDC_req request{}; request.next_hdr=UET_HDR_REQUEST_STD; request.delivery_mode=RUD;
    request.som=request.eom=true; request.pkt.bth_type=Standard_Header;
    auto& semantic=request.pkt.bth_header.Standard_Header;
    semantic.opcode=1; semantic.som=semantic.eom=semantic.dc=1;
    for (uint16_t message=1;message<=3;++message) { semantic.msg_id=message; sender.sesTxReq(&request); }
    while (!sender.tx_pkt_q.empty()) sender.tx_pkt_q.pop(); sender.gen_cm=NONE;
    CHECK(sender.tx_pkt_buffer.count(0) && sender.requestProbe(0));
    CHECK(!sender.requestProbe(0) && sender.unack_cnt==3);
    const auto sent=sender.tx_pkt_q.front(); sender.tx_pkt_q.pop();
    CHECK(sent.PDS_header.RUOD_cp_header.psn==0 && sent.PDS_header.RUOD_cp_header.flags.ar);
    CHECK(sent.PDS_header.RUOD_cp_header.probe_opaque==opaque);
    auto wrong=probe_ack(opaque+1,UINT32_MAX); sender.rxAck(&wrong);
    CHECK(sender.probePending() && sender.unack_cnt==3);
    auto future=probe_ack(opaque,1); sender.rxAck(&future); CHECK(sender.probePending());
    auto close_request=probe_ack(opaque,UINT32_MAX); close_request.PDS_header.RUOD_ack_header.flags.req=2;
    sender.rxAck(&close_request); CHECK(sender.probePending());
    auto valid=probe_ack(opaque,UINT32_MAX);
    valid.congestion_ack.sack_psn_offset=1; valid.congestion_ack.sack_bitmap=1;
    sender.rxAck(&valid);
    CHECK(!sender.probePending() && sender.unack_cnt==2 && sender.clear_psn==UINT32_MAX-1);
    CHECK(sender.tx_pkt_buffer.count(0) && sender.tx_pkt_map.at(0).delivery_confirmed);
    CHECK(sender.rx_rsp_pkt_q.size()==1); // Only strictly-earlier CACK inferred a DEFAULT.
    sender.rxAck(&valid); CHECK(sender.rx_rsp_pkt_q.size()==1); // A stale opaque cannot update anything.
    sender.freePDC(); CHECK(loop.pending()==0);
}

void probe_retry_lifetime_and_unknown_context() {
    EventLoop loop; Services services{loop,loop,[]{}};
    I_PDC sender(&services); CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    sender.tx_cur_psn=1001; sender.clear_psn=1000;
    CHECK(sender.requestProbe(1001));
    CHECK(sender.tx_pkt_q.front().PDS_header.RUOD_cp_header.payload==1000); sender.tx_pkt_q.pop();
    const auto before=sender.tx_cur_psn;
    loop.run_until(kMillisecond); CHECK(sender.hasPendingWork()); sender.openChk();
    CHECK(sender.tx_pkt_q.size()==1 && sender.tx_pkt_q.front().PDS_header.RUOD_cp_header.flags.retx);
    CHECK(sender.unack_cnt==0 && sender.tx_cur_psn==before && sender.tx_pkt_map.empty());
    sender.freePDC(); CHECK(loop.pending()==0);
    loop.run_until(100*kMillisecond); CHECK(sender.tx_pkt_q.empty());

    PDS_Manager manager(&services); CHECK(manager.initPDSM());
    PDStoNET_pkt unbound{}; unbound.src_fep=1; unbound.dst_fep=2; unbound.PDS_type=RUOD_cp_header;
    auto& control=unbound.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=Probe; control.flags.ar=1; control.spdcid=1; control.dpdcid=MAX_PDC;
    manager.Net_rx_pkt_q.push(unbound); manager.mainChk();
    CHECK(manager.PDStoNet.empty() && manager.PDCtoSES_req.empty() && manager.open_cnt==0);
}

struct ProbeObservation {
    size_t probes=0,retries=0,acknowledgments=0,dropped=0;
    bool lose_first=false,lose_all=false;
    std::optional<uint32_t> initial_sequence;
};
class ProbeAuditPort final : public IPacketPort {
public:
    ProbeAuditPort(IPacketPort& lower,ProbeObservation& observation):lower_(lower),observation_(observation) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Noop)
            observation_.initial_sequence=packet.PDS_header.RUOD_cp_header.psn;
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Probe) {
            ++observation_.probes; observation_.retries+=packet.PDS_header.RUOD_cp_header.flags.retx;
            CHECK(packet.PDS_header.RUOD_cp_header.psn==0 && packet.PDS_header.RUOD_cp_header.flags.ar);
        }
        if (packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.flags.p) {
            ++observation_.acknowledgments;
            if (observation_.lose_first || observation_.lose_all) {
                observation_.lose_first=false; ++observation_.dropped; return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; ProbeObservation& observation_;
};

void probe_reopens_a_peer_window_without_clear_ack(bool lose_probe_ack,bool congestion,bool permanent=false) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    ProbeObservation observation; observation.lose_first=lose_probe_ack; observation.lose_all=permanent;
    ProbeAuditPort source_port(forward,observation),target_port(reverse,observation);
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    source_host.services().mpr_zero_override=4;
    source_host.services().next_probe_opaque=0x7fff; // Exercise a signed wire offset with an unsigned opaque.

    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,256);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,256,7);
    const auto connection=source_host.open_connection(2,1,RUD); CHECK(connection!=UINT16_MAX);
    loop.run_until(100000); // Establish MP_RANGE=4 before submitting data.
    Operation write; write.type=OperationType::Write; write.peer=2; write.delivery_mode=RUD;
    write.remote_key=region.key; write.payload.assign(16,0x5a);
    for (size_t message=0;message<12;++message) { write.remote_offset=message*16; source.submit(write); }
    const Time final_time=permanent?((uint64_t{1}<<(Max_RTO_Retx_Cnt+1))*kMillisecond+100000):5*kMillisecond;
    loop.run_until(final_time,100000);
    Completion completion{}; size_t count=0,successes=0,timeouts=0;
    while (source.poll_completion(completion)) {
        if (completion.status==CompletionStatus::Success) ++successes;
        else { CHECK(permanent && completion.status==CompletionStatus::Timeout); ++timeouts; }
        ++count;
    }
    if (count!=12) {
        std::cerr<<"probe failure permanent="<<permanent<<" congestion="<<congestion<<" success="<<successes
                 <<" timeout="<<timeouts<<" probes="<<observation.probes<<" replies="<<observation.acknowledgments
                 <<" dropped="<<observation.dropped<<" queued="<<source.queued_fragments()<<" leases="<<source.leased_message_ids()<<'\n';
        const size_t begin=trace.events().size()>80?trace.events().size()-80:0;
        for (size_t index=begin;index<trace.events().size();++index) {
            const auto& event=trace.events()[index]; std::cerr<<event.time<<' '<<event.node<<' '<<event.event<<' '<<event.value<<'\n';
        }
    }
    CHECK(count==12 && observation.probes>0 && observation.acknowledgments>0);
    if (permanent) {
        CHECK(successes==4 && timeouts==8 && observation.probes==Max_RTO_Retx_Cnt+1 && observation.dropped==Max_RTO_Retx_Cnt+1);
        CHECK(target.memory().read(1,1,region.key,0,64)==std::vector<uint8_t>(64,0x5a));
        CHECK(target.memory().read(1,1,region.key,64,128)==std::vector<uint8_t>(128,0));
    } else {
        if (lose_probe_ack) CHECK(observation.dropped==1 && observation.retries>0);
        CHECK(target.memory().read(1,1,region.key,0,192)==std::vector<uint8_t>(192,0x5a));
        CHECK(observation.initial_sequence);
        CHECK(source_host.request_connection_probe(connection,uint32_t(*observation.initial_sequence+12)));
        loop.run_until(6*kMillisecond,100000);
        CHECK(source_host.services().next_probe_opaque>1);
    }
    CHECK(source.leased_message_ids()==0 && source.queued_fragments()==0 && target.retained_receive_messages()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        destination_probe_bitmap(RUD); destination_probe_bitmap(ROD);
        probe_opaque_never_acknowledges_a_packet(0); probe_opaque_never_acknowledges_a_packet(1);
        probe_opaque_never_acknowledges_a_packet(0x8000);
        probe_retry_lifetime_and_unknown_context();
        for (const bool loss:{false,true}) for (const bool congestion:{false,true})
            probe_reopens_a_peer_window_without_clear_ack(loss,congestion);
        probe_reopens_a_peer_window_without_clear_ack(false,false,true);
        std::cout<<"PASS Probe opaque/CACK/SACK, unknown-PDC drop, independent retry lifecycle and window recovery\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
