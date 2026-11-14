#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// An independently scripted SES peer drives the original production PDS.
// It neither delivers packets reliably nor deduplicates them. This lets a
// source be tested against J>0 and zero-token re-deferral policies that the
// native header-only/reserved-target policy does not choose to emit.
void restart_suffix(bool tagged,pdc_mode mode,bool early,bool redefer,bool invalid_controls) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2); auto& forged=fabric.add_host(3);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{}); fabric.add_link(1,3,{}); fabric.add_link(3,1,{});
    PdsHost source_host(1,loop,trace,forward),oracle(2,loop,trace,reverse),adversary(3,loop,trace,forged);
    Endpoint source(1,source_host,loop,trace,16);
    source.memory().add_job(1); source.memory().add_job(2);
    oracle.configure_semantic_payload_mtu(16);
    uint32_t source_token=0; uint16_t next_control=100;
    uint32_t round=0,control_success=0,control_errors=0,restart_messages=0;
    bool sent_first=false; std::vector<uint8_t> received;
    std::vector<uint8_t> original(73);
    for (size_t byte=0;byte<original.size();++byte) original[byte]=static_cast<uint8_t>(byte*11+1);
    auto send_control=[&](uint32_t token,uint32_t offset,uint32_t length,uint32_t rank=2,uint32_t job=1,uint32_t local_token=0,uint32_t network_peer=2) {
        SES_PDS_req control{}; control.src_fep=network_peer; control.dst_fep=1; control.source_pid=1;
        control.mode=RUD; control.next_hdr=UET_HDR_REQUEST_STD; control.rod_context=1; control.lock_pdc=true;
        control.tx_pkt_handle=++next_control; control.pkt.bth_type=Standard_Header; control.pkt_len=44;
        auto& header=control.pkt.bth_header.Standard_Header;
        header.opcode=12; header.som=1; header.eom=1; header.rel=1; header.dc=1;
        header.msg_id=control.tx_pkt_handle; header.job_id=job; header.PIDonFEP=1; header.resource_index=1;
        header.initiator=rank; header.buffer_offset=offset; header.request_length=length;
        // Figure3-14 follows local/remote roles: peer token high, this
        // source's token low. Literal halves are intentionally asymmetric.
        header.match_bits=(uint64_t{token}<<32)|(local_token?local_token:source_token);
        CHECK((network_peer==3?adversary:oracle).submit(control));
    };
    const auto send_first=[&] {
        if (sent_first) return; sent_first=true;
        if (invalid_controls) {
            send_control(0x88776655,13,60,2,1,0x10203040); // Unknown source token.
            send_control(0x88776655,13,60,3); // Wrong rank, same FEP.
            send_control(0x88776655,13,60,2,2); // Wrong Job, locally known.
            send_control(0x88776655,74,0); // Offset beyond original bytes.
            send_control(0x88776655,13,60,2,1,0,3); // Wrong network FEP, spoofed correct rank.
            send_control(0x88776655,13,61); // Range exceeds original bytes.
        }
        send_control(redefer?0:0x88776655,13,60);
        if (!redefer) send_control(0x88776655,13,60); // A fresh MID replay must not restart twice.
    };
    const auto control_response=[&](const PDC_SES_rsp& result) {
        CHECK(result.pkt.bth_type==Semantic_Response_Header);
        const auto& semantic=result.pkt.bth_header.Semantic_Response_Header;
        if (semantic.return_code==1) ++control_success;
        else {
            CHECK(semantic.return_code==static_cast<uint8_t>(SemanticReturnCode::OperationViolation) ||
                semantic.return_code==static_cast<uint8_t>(SemanticReturnCode::PermissionViolation) ||
                semantic.return_code==static_cast<uint8_t>(SemanticReturnCode::BadAddress));
            ++control_errors;
        }
    };
    oracle.set_response_handler(control_response); adversary.set_response_handler(control_response);
    oracle.set_request_handler([&](const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        CHECK(header.opcode==(tagged?11:8) && header.job_id==1 && header.initiator==0 && header.hd);
        CHECK(header.match_bits==(tagged?UINT64_MAX:0) && (!header.som || header.diff.som_true.header_data==42));
        if (!source_token) source_token=static_cast<uint32_t>(header.buffer_offset>>32);
        CHECK(source_token && static_cast<uint32_t>(header.buffer_offset>>32)==source_token);
        const bool deferred=round==0 || (redefer && round==1);
        if (header.som && round) {
            ++restart_messages; CHECK(request.delivery_mode==RUD);
            CHECK(header.request_length==(round==1?60:44));
            CHECK(static_cast<uint32_t>(header.buffer_offset)==((redefer && round==1)?0:0x88776655));
            received.clear();
        }
        if (!deferred) received.insert(received.end(),request.pkt.payload.begin(),request.pkt.payload.end());
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.rsp_len=12; response.gtd_del=deferred || header.eom;
        response.rsp.bth_type=Semantic_Response_Header;
        auto& semantic=response.rsp.bth_header.Semantic_Response_Header;
        semantic.opcode=deferred?1:0; semantic.return_code=1; semantic.list=deferred?1:0;
        semantic.job_id=header.job_id; semantic.message_id=header.msg_id;
        semantic.modified_length=deferred?0:header.request_length; semantic.ri_generation=header.ri_generation;
        CHECK(oracle.manager().pushSESResponse(response)); oracle.wake();
        if (!round && early) send_first();
        if (header.eom) {
            if (!round) { ++round; if (!early) send_first(); }
            else if (redefer && round==1) { ++round; send_control(0x88776655,29,44); }
        }
    });
    Operation operation; operation.type=tagged?OperationType::DeferrableTaggedSend:OperationType::DeferrableSend;
    operation.delivery_mode=mode; operation.peer=2; operation.initiator_id=0;
    operation.payload=original; operation.tag=UINT64_MAX; operation.immediate_data=42; operation.context=99;
    const auto submitted=source.submit(operation); loop.run(100000);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.operation==submitted && completion.context==99 &&
        completion.status==CompletionStatus::Success && completion.length==73 && !source.poll_completion(completion));
    CHECK(received==std::vector<uint8_t>(original.begin()+(redefer?29:13),original.end()));
    CHECK(restart_messages==(redefer?2:1) && control_success==2 && control_errors==(invalid_controls?6:0));
    // A valid-shaped late RTR cannot revive an already completed transaction.
    send_control(0x88776655,13,60); loop.run(100000);
    CHECK(control_errors==(invalid_controls?7:1) && !source.poll_completion(completion));
    CHECK(!source.pending() && !source.leased_message_ids() && !source.retained_receive_messages());
    source.close(); source_host.close(); oracle.close(); adversary.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (bool tagged:{false,true}) for (auto mode:{RUD,ROD}) for (bool early:{false,true})
            for (bool redefer:{false,true}) restart_suffix(tagged,mode,early,redefer,true);
        std::cout<<"PASS independent real-PDS RTR peer: suffix slices, early RTR, zero-token re-deferral, identity/range checks and replay\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
