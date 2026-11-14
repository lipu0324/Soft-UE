#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::CMS;
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

namespace {
void pool_refill(pdc_mode mode,bool nscc) {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,51);
    auto& first_port=fabric.add_host(1);
    auto& target_port=fabric.add_host(2);
    auto& waiting_port=fabric.add_host(3);
    fabric.add_link(1,2,{});
    fabric.add_link(2,1,{});
    fabric.add_link(3,2,{});
    fabric.add_link(2,3,{});
    PdsHost first_host(1,loop,trace,first_port),target_host(2,loop,trace,target_port),waiting_host(3,loop,trace,waiting_port);
    if (nscc) {
        auto congestion=NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,176);
        congestion.initial_maximum_window=352;
        first_host.enable_nscc(congestion);
        target_host.enable_nscc(congestion);
        waiting_host.enable_nscc(congestion);
    }
    TfcEngineConfig flow;
    flow.outgoing.payload_mtu_bytes=flow.incoming.payload_mtu_bytes=64;
    flow.receive_context_bytes=flow.receive_pool_bytes=1024; // Exactly one destination CCC.
    first_host.enable_tfc(flow);
    target_host.enable_tfc(flow);
    waiting_host.enable_tfc(flow);
    Endpoint first(1,first_host,loop,trace,64),target(2,target_host,loop,trace,64),waiting(3,waiting_host,loop,trace,64);
    first.memory().add_job(1);
    target.memory().add_job(1);
    waiting.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,128,7);
    uint16_t first_pdc=0;
    size_t no_context_replies=0,waiting_retries=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (frame.source==1 && packet.PDS_type==RUOD_req_header)
            first_pdc=packet.PDS_header.RUOD_req_header.spdcid;
        if (frame.source==3 && packet.PDS_type==RUOD_req_header)
            waiting_retries+=packet.PDS_header.RUOD_req_header.flags.retx;
        if (frame.destination==3 && packet.PDS_type==nack_header &&
            packet.PDS_header.nack_header.nack_code==UET_NO_CCC_AVAIL) {
            ++no_context_replies;
            CHECK(!packet.PDS_header.nack_header.spdcid);
        }
    });
    Operation write;
    write.type=OperationType::Write;
    write.peer=2;
    write.delivery_mode=mode;
    write.remote_key=region.key;
    write.payload.assign(64,1);
    first.submit(write);
    loop.run_until(kMillisecond);
    Completion completion{};
    CHECK(first.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(first_pdc && target_host.tfc()->reserved_receive_bytes()==1024);
    write.remote_offset=64;
    write.payload.assign(64,3);
    waiting.submit(write);
    loop.run_until(2*kMillisecond);
    CHECK(no_context_replies>0 && !waiting.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,64,64)==std::vector<uint8_t>(64,0));
    CHECK(target_host.tfc()->destination_context_count()==1 && target_host.tfc()->reserved_receive_bytes()==1024);
    CHECK(first_host.request_connection_close(first_pdc));
    // Keep the normative 65 ms plaintext SYN safety guard. The waiting
    // source's own delayed retry must recover after the old CCC closes.
    loop.run_until(90*kMillisecond);
    if (!waiting.poll_completion(completion) || completion.status!=CompletionStatus::Success)
        throw std::runtime_error("TFC pool refill failed mode="+std::to_string(mode)+" nscc="+std::to_string(nscc));
    CHECK(!waiting.poll_completion(completion) && waiting_retries>0);
    CHECK(target.memory().read(1,1,region.key,0,64)==std::vector<uint8_t>(64,1));
    CHECK(target.memory().read(1,1,region.key,64,64)==std::vector<uint8_t>(64,3));
    CHECK(target_host.tfc()->destination_context_count()==1 && target_host.tfc()->reserved_receive_bytes()==1024);
    for (const auto& event:trace.events())
        if (event.node==2 && event.event=="tfc_reserved_bytes") CHECK(event.value<=1024);
    first.close();
    waiting.close();
    target.close();
    first_host.close();
    waiting_host.close();
    target_host.close();
    CHECK(first_host.tfc()->source_connection_count()==0 && waiting_host.tfc()->source_connection_count()==0);
    CHECK(target_host.tfc()->reserved_receive_bytes()==0 && target_host.tfc()->destination_context_count()==0);
    CHECK(loop.pending()==0);
}
}

int main() {
    try {
        for (const auto mode : {RUD,ROD})
            for (const bool nscc : {false,true}) pool_refill(mode,nscc);
        std::cout << "4 original PDS NO_CCC/buffer-pool close/refill/retry cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
