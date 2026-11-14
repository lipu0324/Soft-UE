#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void authority(pdc_mode mode,unsigned scenario) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); source.memory().add_job(2);
    target.memory().add_job(1); if (scenario!=1) target.memory().add_job(2);
    target.resources().configure_resource(1,3,ResourceSpace::Rma);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Optimized|3; options.idempotent_safe=true;
    auto permissions=uint8_t{7};
    if (scenario==5) permissions=static_cast<uint8_t>(Access::Read);
    if (scenario==6) options.local_placement_only=true;
    if (scenario==7) options.rendezvous_source_only=true;
    if (scenario==11) options.allow_any_job=true;
    const auto registration_job=scenario==10 || scenario==11?2u:1u;
    const auto region=target.memory().register_storage(registration_job,1,std::make_shared<SparseMemory>(16),permissions,options);
    Operation operation; operation.type=OperationType::Write; operation.header_format=RequestHeaderFormat::Small;
    operation.delivery_mode=mode; operation.peer=2; operation.remote_key=region.key; operation.payload={7};
    auto expected=SemanticReturnCode::Ok;
    switch (scenario) {
    case 0: operation.job=2; expected=SemanticReturnCode::PermissionViolation; break;
    case 1: operation.job=2; expected=SemanticReturnCode::BadJob; break;
    case 2: operation.target_pid=2; target.resources().map_relative_pid(1,2,2);
        target.resources().configure_resource(2,3,ResourceSpace::Rma); expected=SemanticReturnCode::PermissionViolation; break;
    case 3: operation.remote_key=MemoryKeyFormat::Optimized|4; target.resources().configure_resource(1,4,ResourceSpace::Rma);
        expected=SemanticReturnCode::BadMemoryKey; break;
    case 4: operation.remote_offset=16; expected=SemanticReturnCode::BadAddress; break;
    case 5: case 6: case 7: expected=SemanticReturnCode::OperationViolation; break;
    case 8: CHECK(target.memory().deregister(region)); expected=SemanticReturnCode::BadMemoryKey; break;
    case 9: target.resources().configure_resource(1,3,ResourceSpace::Rma,255); expected=SemanticReturnCode::BadGeneration; break;
    case 10: operation.relative_addressing=false; expected=SemanticReturnCode::PermissionViolation; break;
    case 11: operation.relative_addressing=false; break;
    case 12: operation.relative_addressing=false;
        target.memory().register_storage(2,1,std::make_shared<SparseMemory>(16),7,options);
        expected=SemanticReturnCode::BadMemoryKey; break; // Absolute lookup cannot use Job to choose between equal indices.
    case 13: operation.remote_offset=16; operation.payload.clear(); break; // Empty authorized end-of-region access.
    default: throw std::logic_error("unknown optimized authority scenario");
    }
    const auto id=source.submit(operation); loop.run_until(5*kMillisecond);
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.operation==id);
    CHECK(completion.status==(expected==SemanticReturnCode::Ok?CompletionStatus::Success:CompletionStatus::RemoteError));
    CHECK(completion.remote_code==static_cast<uint8_t>(expected));
    if (scenario==9) CHECK(completion.remote_generation==255);
    std::vector<uint8_t> bytes(16); region.storage->read(0,bytes.data(),bytes.size());
    std::vector<uint8_t> expected_bytes(16); if (scenario==11) expected_bytes[0]=7;
    CHECK(bytes==expected_bytes);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion) && !source.pending() &&
        !source.leased_message_ids() && !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
static void boundaries(pdc_mode mode,bool relative,uint16_t index,uint32_t length) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,8192),target(2,target_host,loop,trace,8192);
    source.memory().add_job(0); target.memory().add_job(0);
    target.resources().map_relative_pid(0,0,0); target.resources().configure_resource(0,index,ResourceSpace::Rma);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Optimized|index; options.idempotent_safe=true;
    const auto region=target.memory().register_storage(0,0,std::make_shared<SparseMemory>(UINT64_MAX),7,options);
    Operation operation; operation.type=OperationType::Write; operation.header_format=RequestHeaderFormat::Small;
    operation.delivery_mode=mode; operation.peer=2; operation.job=0; operation.target_pid=0;
    operation.relative_addressing=relative; operation.remote_key=region.key;
    operation.remote_offset=UINT64_MAX-length; operation.payload.assign(length,0x71);
    source.submit(operation); loop.run_until(5*kMillisecond);
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.length==length);
    CHECK(target.memory().read(0,0,region.key,operation.remote_offset,length,index,relative)==operation.payload);
    CHECK(!target.poll_completion(completion) && !source.poll_completion(completion));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
static void source_rejections() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1); PdsHost host(1,loop,trace,port); Endpoint source(1,host,loop,trace,128);
    source.memory().add_job(1);
    for (unsigned scenario=0;scenario<9;++scenario) {
        Operation operation; operation.type=OperationType::Write; operation.header_format=RequestHeaderFormat::Small;
        operation.peer=2; operation.remote_key=MemoryKeyFormat::Optimized|1;
        switch (scenario) {
        case 0: operation.remote_key=1; break;
        case 1: operation.type=OperationType::Send; break;
        case 2: operation.header_format=RequestHeaderFormat::Medium; operation.immediate_data=42; break;
        case 3: operation.type=OperationType::Read; break;
        case 4: operation.type=OperationType::Atomic;
            operation.atomic_datatype=static_cast<IntegerAtomicDatatype>(99); break;
        case 5: operation.type=OperationType::FetchingAtomic; operation.atomic_datatype=static_cast<IntegerAtomicDatatype>(99); break;
        case 6: operation.payload.resize(129); break;
        case 7: operation.header_format=static_cast<RequestHeaderFormat>(123); break;
        case 8: operation.remote_key|=uint64_t{1}<<56; break;
        }
        source.submit(operation); Completion completion{}; CHECK(source.poll_completion(completion));
        CHECK(completion.status==CompletionStatus::Unsupported || completion.status==CompletionStatus::InvalidRequest);
        CHECK(!source.pending() && !source.queued_fragments() && !host.manager().getPDSStatus().open_cnt);
    }
    source.close(); host.close(); CHECK(!loop.pending());
}
static void legacy_capabilities() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42); auto& port=fabric.add_host(1);
    PdsHost host(1,loop,trace,port,PdsHost::WireFormat::LegacySup1); Endpoint source(1,host,loop,trace);
    source.memory().add_job(1);
    CHECK(!source.capabilities().optimized_small_write && !source.capabilities().optimized_medium_write &&
        !source.capabilities().optimized_medium_send && !source.capabilities().optimized_small_atomic &&
        !source.capabilities().optimized_medium_atomic && !source.capabilities().optimized_small_fetching_atomic &&
        !source.capabilities().optimized_medium_fetching_atomic && !source.capabilities().rudi_write && !source.capabilities().rudi_read);
    Operation operation; operation.type=OperationType::Write; operation.peer=2;
    operation.remote_key=MemoryKeyFormat::Optimized|MemoryKeyFormat::IdempotentSafe|1;
    operation.header_format=RequestHeaderFormat::Small;
    source.submit(operation); Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Unsupported);
    operation.header_format=RequestHeaderFormat::Standard; operation.delivery_mode=RUDI; source.submit(operation);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Unsupported);
    source.close(); host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) {
            for (unsigned scenario=0;scenario<14;++scenario) authority(mode,scenario);
            for (bool relative:{false,true}) for (uint16_t index:{uint16_t{0},uint16_t{4095}}) for (uint32_t length:{0u,1u,8192u})
                boundaries(mode,relative,index,length);
        }
        source_rejections(); legacy_capabilities();
        std::cout<<"PASS62 optimized MR authority, zero/index/address/MTU boundaries, rejected source requests and legacy capabilities\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
