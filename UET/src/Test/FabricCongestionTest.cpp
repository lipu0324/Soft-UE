#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::NetworkLayer;

Frame data_frame(size_t length,uint8_t traffic_class=0,uint8_t ecn=2,bool ipv6=false) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
    auto& request=packet.PDS_header.RUOD_req_header;
    request.type=ROD_REQ; request.next_hdr=UET_HDR_REQUEST_STD; request.psn=1000;
    packet.SESpkt.bth_type=Standard_Header;
    auto& semantic=packet.SESpkt.bth_header.Standard_Header;
    semantic.opcode=1; semantic.som=1; semantic.eom=1;
    const size_t overhead=14+(ipv6?40:20)+8+12+44+4;
    CHECK(length>=overhead); packet.SESpkt.payload.resize(length-overhead);
    semantic.request_length=packet.SESpkt.payload.size();
    WireOptions options; options.ecn=ecn; options.ipv6=ipv6;
    Frame frame; frame.source=1; frame.destination=2; frame.traffic_class=traffic_class;
    frame.bytes=UetWireCodec::encode(packet,options); CHECK(frame.bytes.size()==length);
    return frame;
}

void mark_at_dequeue(bool ipv6) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,1);
    auto& source=fabric.add_host(1); auto& target=fabric.add_host(2);
    LinkConfig config; config.rate_bps=8000000000ULL; config.delay_ns=0;
    config.mtu=512; config.buffer_bytes=2048; config.ecn_threshold_bytes[0]=1024;
    fabric.add_link(1,2,config);
    std::vector<uint8_t> received_ecn;
    target.set_receiver([&](Frame frame) {
        received_ecn.push_back(UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).network.ecn);
        CHECK(frame.has_arrival_timestamp && frame.first_byte_arrival_ns==loop.now()-512);
    });
    for (unsigned packet=0;packet<4;++packet) CHECK(source.try_send(data_frame(512,0,2,ipv6))==SendResult::Accepted);
    loop.run();
    CHECK(received_ecn==std::vector<uint8_t>({2,3,3,2})); // Last packet sees the drained queue, not its enqueue peak.
    CHECK(fabric.stats(1,2).ecn_marked==2 && fabric.stats(1,2).peak_by_class[0]==2048);
    received_ecn.clear();
    for (unsigned packet=0;packet<4;++packet) source.try_send(data_frame(512,0,0,ipv6));
    loop.run(); CHECK(received_ecn==std::vector<uint8_t>({0,0,0,0})); // Never mark a Not-ECT packet.
    CHECK(fabric.stats(1,2).ecn_marked==2);
}

void independent_classes_and_fair_service() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,2);
    auto& source=fabric.add_host(1); auto& target=fabric.add_host(2);
    LinkConfig config; config.rate_bps=8000000000ULL; config.delay_ns=0;
    config.mtu=512; config.buffer_bytes=1024; fabric.add_link(1,2,config);
    std::vector<uint8_t> classes;
    target.set_receiver([&](Frame frame) { classes.push_back(frame.traffic_class); });
    source.try_send(data_frame(512)); source.try_send(data_frame(512)); source.try_send(data_frame(512));
    source.try_send(data_frame(128,1));
    CHECK(fabric.stats(1,2).dropped==1 && fabric.stats(1,2).queued_by_class[1]==128);
    loop.run(); CHECK(classes==std::vector<uint8_t>({0,1,0}));

    EventLoop fair_loop; Trace fair_trace(fair_loop); Fabric fair(fair_loop,fair_trace,3);
    auto& fair_source=fair.add_host(1); auto& fair_target=fair.add_host(2);
    config.buffer_bytes=65536; fair.add_link(1,2,config);
    std::array<size_t,2> delivered_bytes{};
    fair_target.set_receiver([&](Frame frame) { delivered_bytes[frame.traffic_class]+=frame.bytes.size(); });
    for (unsigned packet=0;packet<20;++packet) fair_source.try_send(data_frame(512));
    for (unsigned packet=0;packet<100;++packet) fair_source.try_send(data_frame(128,1));
    fair_loop.run_until(4000);
    CHECK(delivered_bytes[0]>0 && delivered_bytes[1]>0);
    const auto difference=delivered_bytes[0]>delivered_bytes[1]?delivered_bytes[0]-delivered_bytes[1]:delivered_bytes[1]-delivered_bytes[0];
    CHECK(difference<=512); // Byte fairness despite very different packet lengths.
    fair_loop.run();
    CHECK(delivered_bytes[0]==20*512 && delivered_bytes[1]==100*128);
}

void interrupted_link_does_not_resurrect_frames() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,4);
    auto& source=fabric.add_host(1); auto& target=fabric.add_host(2);
    LinkConfig config; config.rate_bps=8000000000ULL; config.delay_ns=0; config.mtu=512; config.buffer_bytes=1024;
    fabric.add_link(1,2,config); size_t delivered=0;
    target.set_receiver([&](Frame) { ++delivered; });
    source.try_send(data_frame(512)); source.try_send(data_frame(512));
    loop.at(100,[&] { fabric.set_link_up(1,2,false); });
    loop.at(200,[&] { fabric.set_link_up(1,2,true); source.try_send(data_frame(512)); });
    loop.run(); CHECK(delivered==1 && fabric.stats(1,2).dropped==2);
    CHECK(fabric.stats(1,2).queued_bytes==0);
}

int main() {
    mark_at_dequeue(false); mark_at_dequeue(true);
    independent_classes_and_fair_service(); interrupted_link_does_not_resurrect_frames();
    std::cout<<"PASS dequeue ECN, independent traffic classes, byte-fair queues and link failure generations\n";
}
