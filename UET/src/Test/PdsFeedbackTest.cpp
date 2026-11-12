#include "Check.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include "../PDS/DefaultSemanticResponse.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

PDStoNET_pkt incoming_request(uint32_t sequence,uint16_t entropy,uint8_t ecn,bool retransmitted) {
    PDStoNET_pkt packet{}; packet.src_fep=1; packet.dst_fep=2; packet.PDS_type=RUOD_req_header;
    auto& transport=packet.PDS_header.RUOD_req_header;
    transport.type=RUD_REQ; transport.next_hdr=UET_HDR_REQUEST_STD;
    transport.psn=sequence; transport.spdcid=1; transport.dpdcid=MAX_PDC;
    transport.flags.ar=1; transport.flags.retx=retransmitted; transport.clear_psn_off=static_cast<int16_t>(999-sequence);
    packet.SESpkt.bth_type=Standard_Header;
    auto& semantic=packet.SESpkt.bth_header.Standard_Header;
    semantic.som=semantic.eom=semantic.dc=1; semantic.job_id=1; semantic.msg_id=sequence-999;
    packet.wire_entropy=entropy; packet.network_ecn=ecn; packet.nominal_packet_size=128;
    return packet;
}

void triggering_packet_feedback(bool congestion) {
    EventLoop loop; Services services{loop,loop,[]{}};
    UET::CMS::NsccEngine engine(UET::CMS::NsccConfig{},loop,[]{},{});
    if (congestion) services.congestion_control=&engine;
    T_PDC target(&services); CHECK(target.initPDC(MAX_PDC));
    target.src_fep=2; target.dst_fep=1; target.mode=RUD; target.state=ESTABLISHED; target.DPDCID=1;
    target.rx_cur_psn=target.cack_psn=target.rx_clear_psn=999;
    auto first=incoming_request(1000,0x1111,3,false),second=incoming_request(1001,0x2222,2,true);
    second.receive_time_ns=128;
    target.rxReq(&first); target.rxReq(&second); CHECK(target.rx_req_pkt_q.size()==2);
    const auto first_request=target.rx_req_pkt_q.front(); target.rx_req_pkt_q.pop();
    const auto second_request=target.rx_req_pkt_q.front(); target.rx_req_pkt_q.pop();
    loop.run_until(256);
    auto respond=[&](const PDC_SES_req& request,bool guaranteed) {
        SES_PDC_rsp result{}; result.rx_pkt_handle=request.rx_pkt_handle; result.rep_len=12; result.gtd_del=guaranteed;
        result.pkt=UET::PDS::default_semantic_response(request.pkt); target.sesTxRsp(&result);
    };
    // Responses deliberately finish in the opposite order. A single "last
    // received packet" variable would attribute the first response incorrectly.
    respond(second_request,false);
    auto acknowledgment=target.tx_pkt_q.front(); target.tx_pkt_q.pop();
    CHECK(acknowledgment.wire_entropy==0x2222 && !acknowledgment.PDS_header.RUOD_ack_header.flags.m);
    CHECK(acknowledgment.PDS_header.RUOD_ack_header.flags.retx);
    if (congestion) CHECK(acknowledgment.congestion_ack.service_time==1);
    respond(first_request,true);
    acknowledgment=target.tx_pkt_q.front(); target.tx_pkt_q.pop();
    CHECK(acknowledgment.wire_entropy==0x1111 && acknowledgment.PDS_header.RUOD_ack_header.flags.m);
    CHECK(!acknowledgment.PDS_header.RUOD_ack_header.flags.retx);
    if (congestion) CHECK(acknowledgment.congestion_ack.service_time==2);
    CHECK(target.rx_pkt_map.empty());

    PDStoNET_pkt query{}; query.PDS_type=RUOD_cp_header;
    auto& control=query.PDS_header.RUOD_cp_header;
    control.ctl_type=ACK_req; control.flags.ar=1; control.psn=1000;
    query.wire_entropy=0x3333; query.receive_time_ns=256;
    loop.run_until(512); target.rxCtrlAckReq(&query);
    acknowledgment=target.tx_pkt_q.front(); target.tx_pkt_q.pop();
    CHECK(acknowledgment.wire_entropy==0x3333 && !acknowledgment.PDS_header.RUOD_ack_header.flags.m);
    CHECK(!acknowledgment.PDS_header.RUOD_ack_header.flags.retx);
    if (congestion) CHECK(acknowledgment.congestion_ack.service_time==2);

    first.PDS_header.RUOD_req_header.flags.retx=1; first.wire_entropy=0x4444; first.receive_time_ns=512;
    loop.run_until(640); target.rxReq(&first);
    acknowledgment=target.tx_pkt_q.front(); target.tx_pkt_q.pop();
    CHECK(acknowledgment.wire_entropy==0x4444 && acknowledgment.PDS_header.RUOD_ack_header.flags.m);
    CHECK(acknowledgment.PDS_header.RUOD_ack_header.flags.retx);
    if (congestion) CHECK(acknowledgment.congestion_ack.service_time==1);

    auto invalid=incoming_request(1002,0x5555,3,true);
    invalid.PDS_header.RUOD_req_header.flags.syn=1; invalid.PDS_header.RUOD_req_header.psn_off=0;
    target.rxReq(&invalid); const auto negative=target.tx_pkt_q.front(); target.tx_pkt_q.pop();
    CHECK(negative.PDS_type==nack_header && negative.wire_entropy==0x5555);
    CHECK(negative.PDS_header.nack_header.flags.m && negative.PDS_header.nack_header.flags.retx);

    control.ctl_type=Close_cmd; control.psn=1002; control.flags.retx=1;
    query.wire_entropy=0x6666; query.network_ecn=2; query.receive_time_ns=640;
    ThreadSafeQueue<PDStoNET_pkt> close_output; target.public_net_queue=&close_output;
    target.netRxCm(&query); target.close();
    CHECK(close_output.pop(acknowledgment));
    CHECK(acknowledgment.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_CP_ACK);
    CHECK(acknowledgment.wire_entropy==0x6666 && !acknowledgment.PDS_header.RUOD_ack_header.flags.m);
    CHECK(acknowledgment.PDS_header.RUOD_ack_header.flags.retx);
    CHECK(loop.pending()==0);
}

struct EntropyObservation {
    std::map<uint32_t,uint16_t> trigger_entropy;
    size_t acknowledgments=0,controls=0;
    uint16_t local_pdc=UINT16_MAX;
};
class EntropyAuditPort final : public IPacketPort {
public:
    EntropyAuditPort(IPacketPort& lower,EntropyObservation& observation,bool forward)
        :lower_(lower),observation_(observation),forward_(forward) {}
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto& packet=decoded.packet;
        CHECK(frame.entropy==decoded.network.entropy); // Fabric ECMP and wire must agree.
        if (forward_ && packet.PDS_type==RUOD_req_header) {
            observation_.local_pdc=packet.PDS_header.RUOD_req_header.spdcid;
            observation_.trigger_entropy[packet.PDS_header.RUOD_req_header.psn]=decoded.network.entropy;
        }
        if (forward_ && packet.PDS_type==RUOD_cp_header) {
            ++observation_.controls;
            const auto& control=packet.PDS_header.RUOD_cp_header;
            if (control.flags.ar) observation_.trigger_entropy[control.psn]=decoded.network.entropy;
        }
        if (!forward_ && packet.PDS_type==RUOD_ack_header) {
            ++observation_.acknowledgments;
            const auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
            const uint32_t sequence=acknowledgment.cack_psn+acknowledgment.ack_psn_off;
            CHECK(decoded.network.entropy==observation_.trigger_entropy.at(sequence));
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; EntropyObservation& observation_; bool forward_;
};

void actual_wire_feedback(bool ipv6,bool udp,bool congestion,bool ordered) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    EntropyObservation observation;
    EntropyAuditPort source_port(forward,observation,true),target_port(reverse,observation,false);
    WireOptions source_wire,target_wire;
    source_wire.ipv6=target_wire.ipv6=ipv6; source_wire.udp=target_wire.udp=udp;
    source_wire.entropy=0xbeef; target_wire.entropy=0x9876;
    PdsHost source_host(1,loop,trace,source_port,PdsHost::WireFormat::Uet11,source_wire);
    PdsHost target_host(2,loop,trace,target_port,PdsHost::WireFormat::Uet11,target_wire);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,256);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,48,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.delivery_mode=ordered?ROD:RUD;
    write.remote_key=region.key; write.payload.assign(48,0x5a); source.submit(write);
    loop.run_until(kMillisecond);
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(source_host.request_connection_close(observation.local_pdc)); loop.run_until(100*kMillisecond,100000);
    CHECK(observation.acknowledgments>=4 && observation.controls>=2);
    CHECK(target.memory().read(1,1,region.key,0,48)==write.payload);
    if (!congestion) for (const auto& item:observation.trigger_entropy) CHECK(item.second==0xbeef);
    if (ordered) {
        const auto fixed=observation.trigger_entropy.begin()->second;
        for (const auto& item:observation.trigger_entropy) CHECK(item.second==fixed);
    }
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

void controls_do_not_charge_the_data_window() {
    EventLoop loop; UET::CMS::NsccEngine engine(UET::CMS::NsccConfig{},loop,[]{},{});
    for (const bool ordered:{false,true}) {
        const UET::CMS::Connection connection{2,static_cast<uint16_t>(ordered?2:1),1000,ordered};
        PDStoNET_pkt first{}; engine.decorate_control(connection,first);
        const auto before=engine.state(connection).inflight_bytes;
        PDStoNET_pkt next{}; engine.decorate_control(connection,next);
        CHECK(engine.state(connection).inflight_bytes==before);
        CHECK(ordered?(first.wire_entropy==next.wire_entropy):(first.wire_entropy!=next.wire_entropy));
        auto data=incoming_request(1000,0,0,false); engine.transmitted(connection,data);
        if (ordered) CHECK(data.wire_entropy==first.wire_entropy);
        const auto charged=engine.state(connection).inflight_bytes;
        engine.decorate_control(connection,next); CHECK(engine.state(connection).inflight_bytes==charged);
        engine.closed(connection);
    }
    CHECK(engine.congestion_context_count()==0);
}

void unknown_connection_negative_acknowledgment() {
    EventLoop loop; Services services{loop,loop,[]{}}; PDS_Manager manager(&services); CHECK(manager.initPDSM());
    auto packet=incoming_request(1000,0xcafe,3,true); packet.PDS_header.RUOD_req_header.dpdcid=42;
    manager.Net_rx_pkt_q.push(packet); manager.mainChk();
    PDStoNET_pkt negative{}; CHECK(manager.PDStoNet.pop(negative));
    CHECK(negative.PDS_type==nack_header && negative.wire_entropy==0xcafe);
    CHECK(negative.PDS_header.nack_header.flags.m && negative.PDS_header.nack_header.flags.retx);
}

int main() {
    try {
        for (bool congestion:{false,true}) triggering_packet_feedback(congestion);
        for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (bool congestion:{false,true}) for (bool ordered:{false,true})
            actual_wire_feedback(ipv6,udp,congestion,ordered);
        controls_do_not_charge_the_data_window(); unknown_connection_negative_acknowledgment();
        std::cout<<"PASS triggering-packet EV/CE/RETX, response reordering/replay, control paths and all wire encapsulations\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
