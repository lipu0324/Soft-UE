#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::NetworkLayer;

void control_only_contexts(bool ordered,bool negotiation) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& first_port=fabric.add_host(1); auto& second_port=fabric.add_host(2); auto& third_port=fabric.add_host(3);
    for (uint32_t peer:{2,3}) { fabric.add_link(1,peer,{}); fabric.add_link(peer,1,{}); }
    PdsHost first(1,loop,trace,first_port),second(2,loop,trace,second_port),third(3,loop,trace,third_port);
    for (auto* host:{&first,&second,&third}) host->enable_nscc({});
    const auto mode=ordered?ROD:RUD;
    const auto first_context=first.open_connection(2,1,mode,negotiation);
    const auto second_context=first.open_connection(2,2,mode,negotiation);
    const auto third_context=first.open_connection(3,1,mode,negotiation);
    CHECK(first_context!=UINT16_MAX && second_context!=UINT16_MAX && third_context!=UINT16_MAX);
    // §3.6.8.1.1: allocation happens synchronously with PDC creation, before
    // progress, control transmission, data admission or any remote feedback.
    CHECK(first.nscc()->source_connection_count()==3);
    CHECK(first.nscc()->congestion_context_count()==(ordered?3u:2u));
    CHECK(second.nscc()->source_connection_count()==0 && third.nscc()->source_connection_count()==0);
    CHECK(first.open_connection(2,1,mode,negotiation)==first_context);
    CHECK(first.nscc()->source_connection_count()==3);
    size_t data_packets=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        data_packets+=packet.PDS_type==RUOD_req_header;
        // RUD can use ACK_CC for SACK/MPR even without data. CCC allocation
        // alone must not fabricate received-byte credit for these controls.
        if (packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.type==ACK_CC)
            CHECK(packet.congestion_ack.received_byte_units==0);
    });
    loop.run_until(10*kMillisecond);
    CHECK(second.manager().hasEstablishedPDC() && third.manager().hasEstablishedPDC());
    CHECK(second.nscc()->source_connection_count()==2 && third.nscc()->source_connection_count()==1);
    CHECK(second.nscc()->congestion_context_count()==(ordered?2u:1u));
    CHECK(third.nscc()->congestion_context_count()==1);
    CHECK(!data_packets);
    CHECK(!first.nscc()->receive_sample_count() && !second.nscc()->receive_sample_count());
    CHECK(std::count_if(trace.events().begin(),trace.events().end(),[](const auto& event) {
        return event.event=="nscc_pdc_bound";
    })==6);

    CHECK(first.request_connection_close(first_context)); loop.run();
    CHECK(first.nscc()->source_connection_count()==2 && first.nscc()->congestion_context_count()==2);
    CHECK(second.nscc()->source_connection_count()==1 && second.nscc()->congestion_context_count()==1);
    CHECK(first.request_connection_close(second_context)); loop.run();
    CHECK(first.nscc()->source_connection_count()==1 && first.nscc()->congestion_context_count()==1);
    CHECK(!second.nscc()->source_connection_count() && !second.nscc()->congestion_context_count());
    CHECK(first.request_connection_close(third_context)); loop.run();
    for (auto* host:{&first,&second,&third}) {
        CHECK(!host->nscc()->source_connection_count() && !host->nscc()->congestion_context_count());
        host->close();
    }
    CHECK(loop.pending()==0);
}

void failed_open_and_resource_refusal(pdc_mode mode) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1); fabric.add_host(2);
    LinkConfig lost; lost.drop_ppm=1000000; fabric.add_link(1,2,lost); fabric.add_link(2,1,{});
    PdsHost host(1,loop,trace,port); host.enable_nscc({});
    host.services().initiator_context_limit=1;
    CHECK(host.open_connection(2,1,mode)!=UINT16_MAX);
    CHECK(host.nscc()->source_connection_count()==1 && host.nscc()->congestion_context_count()==1);
    CHECK(host.open_connection(2,2,mode)==UINT16_MAX);
    CHECK(host.nscc()->source_connection_count()==1 && host.nscc()->congestion_context_count()==1);
    loop.run(100000);
    CHECK(!host.nscc()->source_connection_count() && !host.nscc()->congestion_context_count());
    CHECK(host.manager().getPDSStatus().open_cnt==0);
    // Reuse after failed SYN must bind a fresh PDC incarnation, then release
    // it even when the application closes before its first progress call.
    CHECK(host.open_connection(2,2,mode)!=UINT16_MAX);
    CHECK(host.nscc()->source_connection_count()==1 && host.nscc()->congestion_context_count()==1);
    host.close(); CHECK(!host.nscc()->source_connection_count() && !host.nscc()->congestion_context_count());
    CHECK(loop.pending()==0);
}

void invalid_syn_never_binds() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source=fabric.add_host(1); auto& destination=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost target(2,loop,trace,destination); target.enable_nscc({});
    TrimmingOptions trimming; target.configure_trimming(trimming);
    source.set_receiver([](Frame) {});
    WireOptions network; network.source.ip[3]=1; network.destination.ip[3]=2;
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
    auto& control=packet.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=Noop; control.flags.syn=control.flags.ar=1;
    control.flags.pdc_type=1; control.psn=1000;
    for (const bool trim:{false,true}) {
        control.spdcid=trim?7:0; // Reserved ID rejection, then a trimmed SYN.
        Frame frame; frame.source=1; frame.destination=2; frame.bytes=UetWireCodec::encode(packet,network);
        if (trim) CHECK(UetWireCodec::trim_packet(frame.bytes,trimming));
        CHECK(source.try_send(frame)==SendResult::Accepted); loop.run();
        CHECK(target.manager().getPDSStatus().open_cnt==0);
        CHECK(!target.nscc()->source_connection_count() && !target.nscc()->congestion_context_count());
    }
    target.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (bool ordered:{false,true}) for (bool negotiation:{false,true}) control_only_contexts(ordered,negotiation);
        for (auto mode:{RUD,ROD}) failed_open_and_resource_refusal(mode);
        invalid_syn_never_binds();
        std::cout<<"PASS: CCC binding at PDC creation, RUD sharing, ROD isolation, failed SYN and teardown\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
