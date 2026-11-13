#include "Check.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// Independent PDS source deliberately bypasses source SES validation. The
// target must enforce idempotency, addressing and MR authority on its own.
static void rejected_target_request(unsigned scenario) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_semantic_payload_mtu(64);
    Endpoint target(2,target_host,loop,trace,64);
    target.memory().add_job(1); target.memory().add_job(2);
    const auto safe=target.memory().register_region(1,1,8,7,true);
    const auto unsafe=target.memory().register_region(1,1,8,7);
    const auto read_only=target.memory().register_region(1,1,8,static_cast<uint8_t>(Access::Read),true);
    RegionOptions private_options; private_options.idempotent_safe=true; private_options.local_placement_only=true;
    const auto private_region=target.memory().register_storage(1,1,std::make_shared<SparseMemory>(8),7,private_options);
    private_options.local_placement_only=false; private_options.rendezvous_source_only=true;
    const auto rendezvous_region=target.memory().register_storage(1,1,std::make_shared<SparseMemory>(8),7,private_options);
    target.post_receive(1,1,safe.key,0,4,77);
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.mode=RUDI;
    request.next_hdr=UET_HDR_REQUEST_STD; request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=1; header.som=header.eom=header.rel=header.dc=1;
    header.job_id=1; header.PIDonFEP=header.resource_index=1; header.msg_id=9;
    header.request_length=4; header.match_bits=safe.key; request.pkt.payload={9,8,7,6};
    auto expected=SemanticReturnCode::OperationViolation;
    switch (scenario) {
    case 0: header.job_id=3; expected=SemanticReturnCode::BadJob; break;
    case 1: header.job_id=2; expected=SemanticReturnCode::PermissionViolation; break;
    case 2: header.match_bits^=0x100000; expected=SemanticReturnCode::BadMemoryKey; break;
    case 3: header.PIDonFEP=2; expected=SemanticReturnCode::BadPid; break;
    case 4: header.ri_generation=1; expected=SemanticReturnCode::BadGeneration; break;
    case 5: header.match_bits=read_only.key; break;
    case 6: header.buffer_offset=6; expected=SemanticReturnCode::BadAddress; break;
    case 7: header.match_bits=unsafe.key; break;
    case 8: header.opcode=3; expected=SemanticReturnCode::UnsupportedOperation; break;
    case 9: header.hd=1; expected=SemanticReturnCode::UnsupportedOperation; break;
    case 10: target.memory().deregister(safe.key); expected=SemanticReturnCode::BadMemoryKey; break;
    case 11: header.match_bits=private_region.key; break;
    case 12: header.match_bits=rendezvous_region.key; break;
    case 13: header.buffer_offset=UINT64_MAX; expected=SemanticReturnCode::BadAddress; break;
    case 14: header.som=0; header.diff.som_false.message_offset=3; header.diff.som_false.payload_length=4;
        expected=SemanticReturnCode::UnsupportedSize; break;
    case 15: header.opcode=2; expected=SemanticReturnCode::UnsupportedSize; break;
    case 16: header.opcode=5; expected=SemanticReturnCode::UnsupportedOperation; break;
    case 17: header.ie=1; expected=SemanticReturnCode::InitiatorError; break;
    case 18: header.PIDonFEP=2; target.resources().map_relative_pid(1,2,2);
        target.resources().configure_resource(2,1,ResourceSpace::Rma);
        expected=SemanticReturnCode::PermissionViolation; break;
    default: throw std::logic_error("unknown target rejection scenario");
    }
    std::vector<PDC_SES_rsp> responses;
    source_host.set_response_handler([&](const auto& response) { responses.push_back(response); });
    CHECK(source_host.submit_rudi(request)); loop.run_until(kMillisecond);
    CHECK(responses.size()==1 && !responses.front().rudi_timed_out);
    if (responses.front().pkt.bth_header.Semantic_Response_Header.return_code!=static_cast<uint8_t>(expected))
        std::cerr<<"scenario="<<scenario<<" expected="<<unsigned(expected)<<" actual="
            <<unsigned(responses.front().pkt.bth_header.Semantic_Response_Header.return_code)<<'\n';
    CHECK(responses.front().pkt.bth_header.Semantic_Response_Header.return_code==static_cast<uint8_t>(expected));
    std::vector<uint8_t> unchanged(8); safe.storage->read(0,unchanged.data(),unchanged.size());
    CHECK(unchanged==std::vector<uint8_t>(8));
    Completion completion{}; CHECK(!target.poll_completion(completion));
    CHECK(!target.retained_receive_messages() && !target_host.manager().getPDSStatus().open_cnt);
    target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
static void source_rejections() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1); PdsHost host(1,loop,trace,port); Endpoint source(1,host,loop,trace,64);
    source.memory().add_job(1);
    size_t cases=0;
    for (const auto type:{OperationType::Send,OperationType::TaggedSend,OperationType::Atomic,OperationType::FetchingAtomic,
        OperationType::Noop,OperationType::DatagramSend,OperationType::SynchronizedWrite}) {
        Operation operation; operation.type=type; operation.delivery_mode=RUDI; operation.peer=2;
        operation.remote_key=MemoryRegistry::kIdempotentSafe|1;
        source.submit(operation); Completion completion{}; CHECK(source.poll_completion(completion));
        CHECK(completion.status!=CompletionStatus::Success && !source.pending()); ++cases;
    }
    for (bool immediate:{false,true}) {
        Operation operation; operation.type=OperationType::Write; operation.delivery_mode=RUDI; operation.peer=2;
        operation.remote_key=immediate?(MemoryRegistry::kIdempotentSafe|1):1;
        if (immediate) operation.immediate_data=42;
        source.submit(operation); Completion completion{}; CHECK(source.poll_completion(completion));
        CHECK(completion.status==CompletionStatus::Unsupported); ++cases;
    }
    CHECK(cases==9 && !host.services().next_rudi_packet_id && !source.queued_fragments());
    source.close(); host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (unsigned scenario=0;scenario<19;++scenario) rejected_target_request(scenario);
        source_rejections();
        std::cout<<"PASS28 independent RUDI target authority/idempotency rejections and side-effecting source-operation refusal\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
