#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// Submit below Endpoint's validation. Real PDS assigns PSNs, retransmits and
// performs Clear; target SES must independently reject malformed requests.
static void target_rejection(pdc_mode mode,bool medium,unsigned scenario) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint target(2,target_host,loop,trace,128);
    target.memory().add_job(1); target.resources().configure_resource(1,3,ResourceSpace::Rma);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Optimized|3;
    const auto region=target.memory().register_storage(1,1,std::make_shared<SparseMemory>(256),7,options);
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.tx_pkt_handle=9;
    request.next_hdr=medium?UET_HDR_REQUEST_MEDIUM:UET_HDR_REQUEST_SMALL;
    request.pkt.bth_type=medium?Small_Message_RMA_Header:Optimized_Header;
    const auto configure=[&](auto& header) {
        header.opcode=1; header.som=header.eom=header.rel=header.dc=1;
        header.job_id=1; header.PIDonFEP=1; header.resource_index=3; header.request_length=1;
        switch (scenario) {
        case 0: header.som=0; break;
        case 1: header.eom=0; break;
        case 2: header.request_length=129; break;
        case 3: header.opcode=2; break; // Wire codec supports READ; native optimized READ is not enabled yet.
        case 4: header.ie=1; break;
        case 5: header.request_length=2; break; // Single-packet payload cannot silently truncate.
        }
    };
    if (medium) {
        auto& header=request.pkt.bth_header.Small_Message_RMA_Header;
        configure(header); header.match_bits=region.key;
    } else configure(request.pkt.bth_header.Optimized_Header);
    request.pkt.payload={0x7b}; request.pkt_len=(medium?32:20)+1;
    size_t responses=0;
    source_host.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.original_request_format==request.pkt.bth_type && response.local_submission_id==9);
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(!header.message_id && header.return_code!=static_cast<uint8_t>(SemanticReturnCode::Ok));
        ++responses;
    });
    CHECK(source_host.submit(request)); loop.run_until(10*kMillisecond);
    Completion completion{};
    CHECK(responses==1 && !target.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,256,3)==std::vector<uint8_t>(256));
    CHECK(!target.retained_receive_messages());
    target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

static void failing_local_reader(pdc_mode mode,RequestHeaderFormat format) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Optimized|3;
    target.resources().configure_resource(1,3,ResourceSpace::Rma);
    const auto region=target.memory().register_storage(1,1,std::make_shared<SparseMemory>(256),7,options);
    Operation operation; operation.type=OperationType::Write; operation.peer=2;
    operation.header_format=format; operation.delivery_mode=mode; operation.remote_key=region.key;
    operation.payload_source=std::make_shared<GeneratedPayload>(7,[](uint64_t,uint8_t*,size_t) {
        throw std::runtime_error("injected local reader failure");
    });
    const auto id=source.submit(operation); loop.run_until(10*kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.operation==id && completion.status==CompletionStatus::LocalError);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages());
    CHECK(target.memory().read(1,1,region.key,0,256,3)==std::vector<uint8_t>(256));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool medium:{false,true}) {
            for (unsigned scenario=0;scenario<6;++scenario) target_rejection(mode,medium,scenario);
            failing_local_reader(mode,medium?RequestHeaderFormat::Medium:RequestHeaderFormat::Small);
        }
        std::cout<<"PASS28 independent optimized malformed requests and local reader failure cleanup\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
