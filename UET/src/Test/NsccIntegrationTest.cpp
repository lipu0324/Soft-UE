#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <set>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::CMS;
using UET::NetworkLayer::UetWireCodec;
// 64-byte payload + PDS12 + SES44 + UDP8 + CRC4 + nominal IP40.
constexpr uint32_t nominal_data_packet_bytes=172;

class CongestionFaultPort final : public IPacketPort {
public:
    explicit CongestionFaultPort(IPacketPort& lower):lower_(lower) {}
    bool drop_first_data=false,replace_semantic_ack=false;
    size_t data_packets=0,ack_queries=0,dropped=0;
    std::set<uint16_t> entropies;
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto& packet=decoded.packet;
        if (packet.PDS_type==RUOD_req_header) {
            ++data_packets; entropies.insert(decoded.network.entropy);
            CHECK(decoded.network.ecn==2);
            if (drop_first_data) { drop_first_data=false; ++dropped; return SendResult::Accepted; }
        }
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==ACK_req) ++ack_queries;
        if (replace_semantic_ack && packet.PDS_type==RUOD_ack_header &&
            packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE &&
            (packet.PDS_header.RUOD_ack_header.flags.req&1)) {
            // Lose the guaranteed EOM result. An intermediate DEFAULT can be
            // inferred from a later CACK and need not trigger an ACK Request.
            replace_semantic_ack=false; ++dropped;
            auto receipt=packet; receipt.PDS_header.RUOD_ack_header.next_hdr=UET_HDR_NONE; receipt.SESpkt={};
            auto receipt_frame=frame; receipt_frame.bytes=UetWireCodec::encode(receipt,decoded.network);
            return lower_.try_send(receipt_frame);
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_;
};

void transport_case(bool ordered,bool lose_data,bool lose_semantics) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,47);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    LinkConfig link; link.delay_ns=10000;
    fabric.add_link(1,2,link); fabric.add_link(2,1,link);
    CongestionFaultPort forward(source_port),reverse(target_port);
    forward.drop_first_data=lose_data; reverse.replace_semantic_ack=lose_semantics;
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    auto config=NsccConfig::for_link(100000,12500000000ULL,12500000000ULL,nominal_data_packet_bytes);
    config.initial_maximum_window=nominal_data_packet_bytes; // Exactly one 64-byte payload packet including nominal headers.
    source_host.enable_nscc(config); target_host.enable_nscc(config);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,4096,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=region.key;
    write.delivery_mode=ordered?ROD:RUD; write.payload.resize(1024);
    for (size_t byte=0;byte<write.payload.size();++byte) write.payload[byte]=static_cast<uint8_t>(byte*7);
    source.submit(write);
    loop.run_until(9999);
    CHECK(forward.data_packets==1); // No ACK could return yet: CMS really gates the PDS producer.
    CHECK(source_host.nscc()->congestion_context_count()==1);
    loop.run_until(10*kMillisecond);
    Completion completion{};
    if (!source.poll_completion(completion)) {
        std::cerr<<"Incomplete ordered="<<ordered<<" lose_data="<<lose_data<<" lose_semantics="<<lose_semantics<<'\n';
        for (const auto& event:trace.events()) std::cerr<<event.time<<' '<<event.node<<' '<<event.event<<' '<<event.value<<'\n';
        throw std::runtime_error("NSCC transfer did not complete");
    }
    CHECK(completion.status==CompletionStatus::Success && completion.length==1024);
    CHECK(!source.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,1024)==write.payload);
    CHECK(ordered?forward.entropies.size()==1:forward.entropies.size()>1);
    CHECK(source_host.nscc()->congestion_context_count()<=1); // Normal PDS closure may already retire it.
    if (lose_data) {
        CHECK(forward.dropped==1 && forward.data_packets>16);
        CHECK(std::any_of(trace.events().begin(),trace.events().end(),[](const auto& event) { return event.event=="nscc_inferred_loss"; }));
    }
    if (lose_semantics) {
        CHECK(reverse.dropped==1 && forward.ack_queries>0);
        CHECK(forward.data_packets==16); // A missing SES response never causes duplicate data accounting.
    }
    CHECK(std::any_of(trace.events().begin(),trace.events().end(),[](const auto& event) { return event.event=="nscc_blocked"; }));
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(source_host.nscc()->congestion_context_count()==0 && target_host.nscc()->receive_sample_count()==0);
    CHECK(loop.pending()==0);
}

void context_sharing() {
    EventLoop loop; Trace trace(loop);
    NsccEngine engine(NsccConfig{},loop,[]{},{},&trace);
    const Connection sprayed_one{2,1,1000,false},sprayed_two{2,2,2000,false};
    const Connection ordered_one{2,3,3000,true},ordered_two{2,4,4000,true};
    for (const auto& connection:{sprayed_one,sprayed_two,ordered_one,ordered_two}) CHECK(engine.can_send(connection));
    CHECK(engine.source_connection_count()==4 && engine.congestion_context_count()==3);
    CHECK(&engine.state(sprayed_one)==&engine.state(sprayed_two));
    CHECK(&engine.state(ordered_one)!=&engine.state(ordered_two));
    engine.closed(sprayed_one); CHECK(engine.congestion_context_count()==3);
    engine.closed(sprayed_two); CHECK(engine.congestion_context_count()==2);
    engine.closed(ordered_one); engine.closed(ordered_two); CHECK(engine.congestion_context_count()==0);
}

void duplicate_feedback_and_cancelled_first_send() {
    EventLoop loop; Trace trace(loop);
    NsccEngine engine(NsccConfig{},loop,[]{},{},&trace);
    const Connection receiver{1,512,1000,true};
    PDStoNET_pkt request{}; request.PDS_type=RUOD_req_header;
    request.PDS_header.RUOD_req_header.psn=1000; request.nominal_packet_size=168;
    request.network_ecn=2; request.wire_entropy=7;
    engine.received(receiver,request);
    loop.run_until(256); request.receive_time_ns=256; request.network_ecn=3;
    request.PDS_header.RUOD_req_header.flags.retx=1;
    engine.received(receiver,request,true); loop.run_until(512);
    PDStoNET_pkt response{}; response.PDS_type=RUOD_ack_header;
    engine.decorate_ack(receiver,1000,response);
    CHECK(response.congestion_ack.received_byte_units==1); // Retransmit never increments accepted bytes.
    CHECK(response.PDS_header.RUOD_ack_header.flags.m && response.PDS_header.RUOD_ack_header.flags.retx);
    CHECK(response.congestion_ack.service_time==2 && response.wire_entropy==7);
    engine.closed(receiver); CHECK(engine.receive_sample_count()==0);

    EventLoop cancel_loop; Trace cancel_trace(cancel_loop); Fabric fabric(cancel_loop,cancel_trace,49);
    auto& source_port=fabric.add_host(1); fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost host(1,cancel_loop,cancel_trace,source_port);
    auto config=NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,nominal_data_packet_bytes);
    config.initial_maximum_window=nominal_data_packet_bytes; host.enable_nscc(config);
    Endpoint endpoint(1,host,cancel_loop,cancel_trace,64);
    for (const auto job:{1u,2u}) {
        endpoint.memory().add_job(job);
        Operation write; write.type=OperationType::Write; write.delivery_mode=RUD;
        write.peer=2; write.job=job; write.payload.resize(64); endpoint.submit(write);
    }
    cancel_loop.run_until(0);
    CHECK(host.nscc()->source_connection_count()==2 && host.nscc()->congestion_context_count()==1);
    // Job 2's PDC has been admitted to the shared CCC but has not sent its
    // first request. Cancelling that queue must retain the selected RUD CCC
    // identity until PDC teardown, even while its legacy default mode is ROD.
    endpoint.close(); host.close();
    CHECK(host.nscc()->source_connection_count()==0 && host.nscc()->congestion_context_count()==0);
    cancel_loop.run(); CHECK(cancel_loop.pending()==0);
}

void datagram_ecn_without_reliable_window() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,55);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    source_host.enable_nscc(NsccConfig{}); target_host.enable_nscc(NsccConfig{});
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,32,7);
    target.post_receive(1,1,region.key,0,32);
    size_t datagrams=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        if (decoded.packet.PDS_type==UUD_req_header) { ++datagrams; CHECK(decoded.network.ecn==2); }
    });
    Operation send; send.type=OperationType::DatagramSend; send.peer=2; send.payload={1,2,3};
    source.submit(send); loop.run(); Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::LocalSuccess);
    CHECK(target.poll_completion(completion) && completion.receive && completion.status==CompletionStatus::Success);
    CHECK(datagrams==1 && target.memory().read(1,1,region.key,0,3)==send.payload);
    CHECK(source_host.nscc()->congestion_context_count()==0 && target_host.nscc()->congestion_context_count()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    context_sharing();
    duplicate_feedback_and_cancelled_first_send();
    datagram_ecn_without_reliable_window();
    for (const auto ordered:{false,true}) {
        transport_case(ordered,false,false);
        transport_case(ordered,true,false);
        transport_case(ordered,false,true);
    }
    std::cout<<"PASS NSCC gates original PDS sends/retries, clocks ACK_CC bytes, preserves paths and recovers semantics\n";
}
