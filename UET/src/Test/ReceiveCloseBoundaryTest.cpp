#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void cancel_partial_placement(pdc_mode mode,bool send) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    source.configure_semantic_payload_mtu(4);
    Endpoint target(2,target_host,loop,trace,4); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,8,7);
    if (send) target.post_receive(1,1,region.key,0,8,44);
    source.set_response_handler([](const PDC_SES_rsp&) {});
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header; request.pkt_len=48;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=send?5:1; header.som=header.dc=header.rel=1; header.hd=!send;
    header.msg_id=9; header.job_id=header.PIDonFEP=header.resource_index=1; header.initiator=7;
    header.request_length=8; header.match_bits=region.key; header.diff.som_true.header_data=42;
    request.pkt.payload.assign(4,0xaa); CHECK(source.submit(request)); loop.run_until(kMillisecond);
    Completion completion{}; CHECK(!target.poll_completion(completion));
    target.close();
    if (!target.poll_completion(completion)) throw std::runtime_error("target close lost a partially placed receive completion");
    CHECK(completion.receive && completion.status==CompletionStatus::Cancelled && completion.length==4 &&
        completion.context==(send?44u:0u) && completion.original_length==8);
    CHECK(completion.immediate_data==(send?std::optional<uint64_t>{}:std::optional<uint64_t>{42}));
    CHECK(!target.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,4)==std::vector<uint8_t>(4,0xaa));
    CHECK(target.memory().read(1,1,region.key,4,4)==std::vector<uint8_t>(4));
    source.close(); target_host.close(); loop.run_until(2*kMillisecond); CHECK(!loop.pending());
}
static void cancel_unmatched_complete_send(pdc_mode mode) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    source.configure_semantic_payload_mtu(4); Endpoint target(2,target_host,loop,trace,4); target.memory().add_job(1);
    size_t errors=0;
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(header.return_code==static_cast<uint8_t>(mode==ROD?
            SemanticReturnCode::Undeliverable:SemanticReturnCode::NoMatch) && !header.modified_length); ++errors;
    });
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header; request.pkt_len=48;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=5; header.som=header.eom=header.dc=header.rel=1; header.msg_id=9;
    header.job_id=header.PIDonFEP=header.resource_index=1; header.initiator=7; header.request_length=4;
    request.pkt.payload.assign(4,0xaa); CHECK(source.submit(request)); loop.run_until(kMillisecond);
    // RUD rejects an unmatched SEND immediately; only ROD buffers it and
    // holds a delivery-complete EOM for a future receive posting.
    CHECK(errors==size_t(mode==RUD) && target.unexpected_bytes()==(mode==ROD?4u:0u));
    target.close(); loop.run_until(2*kMillisecond);
    if (errors!=1) throw std::runtime_error("target close orphaned an unmatched SEND EOM RX handle");
    Completion completion{}; CHECK(!target.poll_completion(completion) && !target.unexpected_bytes());
    CHECK(!target_host.services().retired_semantic_receives.size());
    source.close(); target_host.close(); loop.run_until(3*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) {
            for (bool send:{false,true}) cancel_partial_placement(mode,send);
            cancel_unmatched_complete_send(mode);
        }
        std::cout<<"PASS6 target close preserves partial placement/CQ and cancels unmatched final handles\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
