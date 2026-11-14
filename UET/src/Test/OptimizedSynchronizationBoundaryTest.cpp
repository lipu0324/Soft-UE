#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void format_rejection_does_not_consume_member(pdc_mode mode,unsigned scenario) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    target.resources().configure_resource(1,3,ResourceSpace::Rma);
    RegionOptions options; options.resource_index=3;
    options.requested_key=scenario==3?42:MemoryKeyFormat::Optimized|3;
    const auto region=target.memory().register_region(1,1,128,7,options);
    const auto synchronization=source.begin_synchronized_group(2,1,1); CHECK(synchronization);
    Operation operation; operation.type=scenario==3?OperationType::SynchronizedAtomic:OperationType::SynchronizedWrite;
    operation.header_format=scenario==0 || scenario==3?RequestHeaderFormat::Small:RequestHeaderFormat::Medium;
    operation.peer=2; operation.delivery_mode=mode; operation.target_resource=3; operation.remote_key=region.key;
    operation.synchronization=synchronization;
    if (scenario==3) operation.payload={5,0,0,0,0,0,0,0};
    else { operation.payload.assign(scenario==2?65:8,0x53); operation.immediate_data=0; }
    if (scenario==1) operation.remote_offset=8;
    const auto rejected=source.submit(operation);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.operation==rejected &&
        completion.status==(scenario==3?CompletionStatus::InvalidRequest:CompletionStatus::Unsupported));
    CHECK(!source.pending() && source.active_synchronized_source_groups()==1 && !source_host.manager().getPDSStatus().open_cnt);
    CHECK(!target.retained_synchronized_groups() && !target.retained_receive_messages());
    // Reuse the very same local group handle. No failed-format message ever
    // reached PDS or consumed the sole required completing-member slot.
    operation.header_format=RequestHeaderFormat::Standard;
    const auto accepted=source.submit(operation); loop.run_until(90*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.operation==accepted && completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,operation.remote_offset,operation.payload.size(),3)==operation.payload);
    if (scenario!=3) CHECK(target.poll_completion(completion) && completion.receive && completion.status==CompletionStatus::Success &&
        completion.immediate_data==0 && completion.length==operation.payload.size());
    CHECK(!target.poll_completion(completion) && !source.active_synchronized_source_groups() && !source.leased_message_ids() &&
        !target.retained_synchronized_groups() && !target.retained_synchronized_members());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

static void optimized_zero_completer(RequestHeaderFormat format,pdc_mode mode) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Optimized|3; options.resource_index=3;
    target.resources().configure_resource(1,3,ResourceSpace::Rma);
    const auto region=target.memory().register_region(1,1,0,7,options);
    Operation operation; operation.type=OperationType::SynchronizedAtomic; operation.header_format=format;
    operation.peer=2; operation.delivery_mode=mode; operation.remote_key=region.key; operation.target_resource=3;
    operation.atomic_operation=IntegerAtomicOperation::Write; operation.zero_length_atomic=true;
    operation.synchronization=source.begin_synchronized_group(2,1,1); CHECK(operation.synchronization);
    source.submit(operation); loop.run_until(90*kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && !completion.length);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK(!source.pending() && !source.active_synchronized_source_groups() && !source.leased_message_ids() &&
        !target.retained_synchronized_groups() && !target.retained_synchronized_members() && !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

int main() {
    try {
        for (auto mode:{RUD,ROD}) {
            for (unsigned scenario=0;scenario<4;++scenario) format_rejection_does_not_consume_member(mode,scenario);
            for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) optimized_zero_completer(format,mode);
        }
        std::cout << "PASS8 optimized format/member admission rejections and4 zero-length completing atomics\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
