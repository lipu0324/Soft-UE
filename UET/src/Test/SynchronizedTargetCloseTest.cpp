#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// Script the peer's ordering: native source coordination deliberately sends
// its completing atomic last, so it cannot exercise this deferred target case.
static void close_waiting_atomic(pdc_mode mode,bool congestion,uint32_t payload_mtu) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source.configure_semantic_payload_mtu(payload_mtu);
    if (congestion) { source.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint target(2,target_host,loop,trace,payload_mtu,20*kMillisecond);
    target.memory().add_job(1); const auto region=target.memory().register_region(1,1,8,7);
    size_t responses=0;
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(header.message_id==9 && header.return_code==static_cast<uint8_t>(SemanticReturnCode::Undeliverable));
        CHECK(header.modified_length==0); ++responses;
    });
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header; request.pkt.eth_type=Synchronized_Atomic_Extension_Headers;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=0x11; header.som=header.eom=header.dc=header.rel=1;
    header.msg_id=9; header.job_id=header.PIDonFEP=header.resource_index=1;
    header.initiator=7; header.request_length=8; header.match_bits=region.key;
    auto& extension=request.pkt.eth_header.Synchronized_Atomic_Extension_Headers;
    extension.synchronization.sync_group=42; extension.synchronization.sync_count=3;
    extension.atomic.atomic_opcode=static_cast<uint8_t>(IntegerAtomicOperation::Sum);
    extension.atomic.atomic_datatype=static_cast<uint8_t>(payload_mtu<8?
        IntegerAtomicDatatype::Uint8:IntegerAtomicDatatype::Uint64);
    const std::vector<uint8_t> operand{0,0,0,0,0,0,0,5};
    const size_t packets=(operand.size()+payload_mtu-1)/payload_mtu;
    for (uint32_t offset=0;offset<operand.size();offset+=payload_mtu) {
        const auto count=std::min<size_t>(payload_mtu,operand.size()-offset);
        header.som=offset==0; header.eom=offset+count==operand.size();
        if (!header.som) {
            header.diff.som_false.message_offset=offset;
            header.diff.som_false.payload_length=count;
        }
        request.pkt.payload.assign(operand.begin()+offset,operand.begin()+offset+count);
        request.pkt_len=52+count;
        CHECK(source.submit(request));
    }
    loop.run_until(kMillisecond);
    CHECK(!responses && target.retained_synchronized_actions()==1);
    target.close(); loop.run_until(2*kMillisecond);
    if (responses!=packets) throw std::runtime_error("closed target orphaned a deferred synchronized atomic RX handle");
    CHECK(target.memory().read(1,1,region.key,0,8)==std::vector<uint8_t>(8));
    CHECK(!target.retained_synchronized_actions() && !target.retained_synchronized_members());
    Completion completion{}; CHECK(!target.poll_completion(completion));
    source.close(); target_host.close(); loop.run_until(3*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) for (uint32_t payload_mtu:{4,16})
            close_waiting_atomic(mode,congestion,payload_mtu);
        std::cout<<"PASS8 closing a deferred synchronized target returns every fragment error without executing the atomic\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
