#include "Check.hpp"
#include "../PDS/InitialSequenceAllocator.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include <iostream>
#include <tuple>
using namespace UET::Runtime;
using UET::PDS::InitialSequenceAllocator;

void allocator_boundaries() {
    InitialSequenceAllocator first(42),replay(42);
    CHECK(first.reserve(1)==replay.reserve(1));
    uint32_t previous_last=UINT32_MAX-8;
    first.observe_last(1,previous_last); replay.observe_last(1,previous_last);
    for (unsigned incarnation=0;incarnation<20000;++incarnation) {
        const auto start=first.reserve(1); CHECK(start==replay.reserve(1));
        const uint32_t separation=start-previous_last;
        CHECK(separation>=65536 && separation<0x80000000u);
        previous_last=start+incarnation%1024;
        first.observe_last(1,previous_last); replay.observe_last(1,previous_last);
    }
    first.reseed(0); replay.reseed(0);
    const auto reseeded=first.reserve(1); CHECK(reseeded==replay.reserve(1));
    CHECK(uint32_t(reseeded-previous_last)>=65536 && uint32_t(reseeded-previous_last)<0x80000000u);
    check_throws<std::invalid_argument>([&] { first.reserve(0); });
    check_throws<std::logic_error>([&] { first.observe_last(99,1); });
}

using OpenedContext=std::tuple<uint16_t,uint32_t,uint32_t>;
std::vector<OpenedContext> captured_epochs(uint64_t seed) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& second_port=fabric.add_host(2); auto& third_port=fabric.add_host(3);
    for (const auto peer:{2u,3u}) { fabric.add_link(1,peer,{}); fabric.add_link(peer,1,{}); }
    PdsHost source(1,loop,trace,source_port),second(2,loop,trace,second_port),third(3,loop,trace,third_port);
    source.services().initiator_context_limit=1; // Force actual local-ID reuse across different peers.
    source.configure_initial_sequence_seed(seed);
    std::vector<OpenedContext> opened; std::vector<uint32_t> closed;
    size_t negative_acknowledgments=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==nack_header) ++negative_acknowledgments;
        if (frame.source!=1) return;
        if (packet.PDS_type!=RUOD_cp_header) return;
        const auto& control=packet.PDS_header.RUOD_cp_header;
        if (control.ctl_type==Noop) opened.emplace_back(control.spdcid,frame.destination,control.psn);
        else if (control.ctl_type==Close_cmd) closed.push_back(control.psn);
    });
    for (size_t epoch=0;epoch<3;++epoch) {
        if (epoch==1) source.configure_initial_sequence_seed(seed+1); // Reseed preserves the previous local-ID epoch.
        const uint32_t peer=epoch==1?3:2;
        const auto local=source.open_connection(peer,1,RUD); CHECK(local!=UINT16_MAX);
        loop.run(100000); CHECK(opened.size()==epoch+1 && std::get<0>(opened.back())==local);
        CHECK(negative_acknowledgments==0);
        if (epoch) {
            CHECK(local==std::get<0>(opened.front()));
            const uint32_t separation=std::get<2>(opened.back())-closed.back();
            CHECK(separation>=65536 && separation<0x80000000u);
        }
        if (source.manager().getPDSStatus().open_cnt!=1)
            throw std::runtime_error("control context closed unexpectedly: seed="+std::to_string(seed)+", epoch="+std::to_string(epoch));
        check_throws<std::logic_error>([&] { source.configure_initial_sequence_seed(seed); });
        CHECK(source.request_connection_close(local)); loop.run(100000);
        CHECK(closed.size()==epoch+1 && source.manager().getPDSStatus().open_cnt==0);
    }
    source.close(); second.close(); third.close(); CHECK(loop.pending()==0);
    check_throws<std::logic_error>([&] { source.configure_initial_sequence_seed(seed); });
    return opened;
}

int main() {
    try {
        allocator_boundaries();
        CHECK(captured_epochs(42)==captured_epochs(42));
        CHECK(captured_epochs(0)==captured_epochs(0));
        std::cout<<"PASS plaintext PSN epochs, wrap/separation, peer-independent local-ID retention and seeded wire replay\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
