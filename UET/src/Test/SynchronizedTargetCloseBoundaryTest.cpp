#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void close_held_receive(pdc_mode mode,bool congestion,bool partial_atomic) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source.configure_semantic_payload_mtu(4);
    if (congestion) { source.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint target(2,target_host,loop,trace,4,20*kMillisecond);
    target.memory().add_job(1); const auto region=target.memory().register_region(1,1,8,7);
    size_t responses=0;
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(header.message_id==9 && header.return_code==static_cast<uint8_t>(partial_atomic?
            SemanticReturnCode::Undeliverable:SemanticReturnCode::Ok));
        CHECK(header.modified_length==(partial_atomic?0u:4u)); ++responses;
    });
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header;
    request.pkt.eth_type=partial_atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=partial_atomic?0x11:0x10; header.som=header.dc=header.rel=1;
    header.eom=!partial_atomic; header.hd=!partial_atomic;
    header.msg_id=9; header.job_id=header.PIDonFEP=header.resource_index=1;
    header.initiator=7; header.request_length=partial_atomic?8:4; header.match_bits=region.key;
    auto& synchronization=partial_atomic?request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
        request.pkt.eth_header.Synchronized_Operation_Extension_Header;
    synchronization.sync_group=42; synchronization.sync_count=3;
    if (partial_atomic) {
        auto& atomic=request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.atomic;
        atomic.atomic_opcode=static_cast<uint8_t>(IntegerAtomicOperation::Sum);
        atomic.atomic_datatype=static_cast<uint8_t>(IntegerAtomicDatatype::Uint8);
        request.pkt.payload.assign(4,5);
    } else { header.diff.som_true.header_data=42; request.pkt.payload.assign(4,0x33); }
    request.pkt_len=44+(partial_atomic?8:4)+4;
    CHECK(source.submit(request)); loop.run_until(kMillisecond);
    CHECK(responses==size_t(!partial_atomic) && target.retained_synchronized_actions()==size_t(!partial_atomic));
    Completion completion{}; CHECK(!target.poll_completion(completion));
    target.close(); loop.run_until(2*kMillisecond);
    if (responses!=1) throw std::runtime_error(partial_atomic?"closed target orphaned a partial synchronized atomic RX handle":
        "closed target answered an acknowledged synchronized WRITE more than once");
    std::vector<uint8_t> expected(8); if (!partial_atomic) std::fill_n(expected.begin(),4,0x33);
    CHECK(target.memory().read(1,1,region.key,0,8)==expected);
    if (!partial_atomic) CHECK(target.poll_completion(completion) && completion.status==CompletionStatus::Cancelled &&
        completion.receive && completion.immediate_data==42 && completion.length==4);
    CHECK(!target.poll_completion(completion));
    source.close(); target_host.close(); loop.run_until(3*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) for (bool partial_atomic:{true,false})
            close_held_receive(mode,congestion,partial_atomic);
        std::cout<<"PASS8 closing partial synchronized atomics and completing writes preserves placement and terminal errors\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
