#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// The domain and its valid MR deliberately survive replacing SES. Rejecting
// an old continuation must follow message ownership, not an accidental bad key.
static void old_continuation_is_not_adopted(pdc_mode mode,bool congestion,bool one_message_credit) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    source.configure_semantic_payload_mtu(4);
    if (congestion) { source.enable_nscc({}); target_host.enable_nscc({}); }
    MemoryRegistry domain; domain.add_job(1); domain.add_job(2); const auto region=domain.register_region(1,1,16,7);
    Endpoint previous(2,target_host,loop,trace,4,20*kMillisecond,&domain);
    size_t errors=0,new_results=0;
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        if (header.message_id==10) {
            CHECK(header.job_id==2 && header.return_code==static_cast<uint8_t>(SemanticReturnCode::Ok)); ++new_results; return;
        }
        if (header.return_code!=static_cast<uint8_t>(SemanticReturnCode::Ok)) {
            CHECK(header.return_code==static_cast<uint8_t>(SemanticReturnCode::Undeliverable)); ++errors;
        }
    });
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header; request.pkt_len=48;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=1; header.som=header.dc=header.rel=1; header.msg_id=9;
    header.job_id=header.PIDonFEP=header.resource_index=1; header.initiator=7;
    header.request_length=8; header.match_bits=region.key; request.pkt.payload.assign(4,0xaa);
    CHECK(source.submit(request)); loop.run_until(kMillisecond);
    CHECK(domain.read(1,1,region.key,0,4)==std::vector<uint8_t>(4,0xaa));
    previous.close(); Endpoint replacement(2,target_host,loop,trace,4,20*kMillisecond,&domain,8,one_message_credit?1:4096);
    CHECK(target_host.services().retired_semantic_receives.size()==1);
    if (one_message_credit) {
        auto blocked=request; auto& fresh=blocked.pkt.bth_header.Standard_Header;
        fresh.opcode=0; fresh.som=fresh.eom=1; fresh.msg_id=10; fresh.job_id=2;
        fresh.request_length=0; fresh.match_bits=0; blocked.tx_pkt_handle=10;
        blocked.pkt.payload.clear(); blocked.pkt_len=44;
        // Job2 selects a separate PDC. Its new message cannot bypass the
        // old Job1 receive credit merely because SES has been replaced.
        CHECK(source.submit(blocked)); loop.run_until(kMillisecond+100000);
        CHECK(!new_results && target_host.services().retired_semantic_receives.size()==1);
    }
    header.som=0; header.eom=1; header.diff.som_false.message_offset=4;
    header.diff.som_false.payload_length=4; request.pkt.payload.assign(4,0xbb);
    CHECK(source.submit(request)); loop.run_until(2*kMillisecond);
    if (domain.read(1,1,region.key,4,4)!=std::vector<uint8_t>(4))
        throw std::runtime_error("replacement Endpoint placed a closed receiver's continuation into the live MR");
    CHECK(errors==1);
    CHECK(!target_host.services().retired_semantic_receives.size());
    loop.run_until(4*kMillisecond); CHECK(new_results==size_t(one_message_credit));
    // Clear retired the old EOM. Reusing the same wire MID now denotes a new
    // message and must reach the replacement normally, through the same PDS.
    header.som=header.eom=1; header.request_length=4; header.buffer_offset=8;
    header.diff.som_true.header_data=0; request.pkt.payload.assign(4,0xcc);
    CHECK(source.submit(request)); loop.run_until(5*kMillisecond);
    CHECK(domain.read(1,1,region.key,8,4)==std::vector<uint8_t>(4,0xcc));
    CHECK(errors==1);
    replacement.close(); source.close(); target_host.close(); loop.run_until(6*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) for (bool one_message_credit:{false,true})
            old_continuation_is_not_adopted(mode,congestion,one_message_credit);
        std::cout<<"PASS8 replaced SES isolates old continuations, credits and legal reuse after Clear\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
