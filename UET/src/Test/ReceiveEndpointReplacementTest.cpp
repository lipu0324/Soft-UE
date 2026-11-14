#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// The domain and its valid MR deliberately survive replacing SES. Rejecting
// an old continuation must follow message ownership, not an accidental bad key.
static void old_continuation_is_not_adopted(pdc_mode mode,bool congestion) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    source.configure_semantic_payload_mtu(4);
    if (congestion) { source.enable_nscc({}); target_host.enable_nscc({}); }
    MemoryRegistry domain; domain.add_job(1); const auto region=domain.register_region(1,1,16,7);
    Endpoint previous(2,target_host,loop,trace,4,20*kMillisecond,&domain);
    size_t errors=0;
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
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
    previous.close(); Endpoint replacement(2,target_host,loop,trace,4,20*kMillisecond,&domain);
    CHECK(target_host.services().retired_semantic_receives.size()==1);
    header.som=0; header.eom=1; header.diff.som_false.message_offset=4;
    header.diff.som_false.payload_length=4; request.pkt.payload.assign(4,0xbb);
    CHECK(source.submit(request)); loop.run_until(2*kMillisecond);
    if (domain.read(1,1,region.key,4,4)!=std::vector<uint8_t>(4))
        throw std::runtime_error("replacement Endpoint placed a closed receiver's continuation into the live MR");
    CHECK(errors==1);
    CHECK(!target_host.services().retired_semantic_receives.size());
    // Clear retired the old EOM. Reusing the same wire MID now denotes a new
    // message and must reach the replacement normally, through the same PDS.
    header.som=header.eom=1; header.request_length=4; header.buffer_offset=8;
    header.diff.som_true.header_data=0; request.pkt.payload.assign(4,0xcc);
    CHECK(source.submit(request)); loop.run_until(3*kMillisecond);
    CHECK(domain.read(1,1,region.key,8,4)==std::vector<uint8_t>(4,0xcc));
    CHECK(errors==1);
    replacement.close(); source.close(); target_host.close(); loop.run_until(4*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) old_continuation_is_not_adopted(mode,congestion);
        std::cout<<"PASS4 replaced SES rejects old continuations while preserving the already placed prefix\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
