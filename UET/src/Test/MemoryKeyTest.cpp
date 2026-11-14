#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

void key_format_and_scopes() {
    MemoryKeyFormat::validate(0,KeyAssignment::Application);
    MemoryKeyFormat::validate(MemoryKeyFormat::Rkey|MemoryKeyFormat::IdempotentSafe,KeyAssignment::Application);
    MemoryKeyFormat::validate(MemoryKeyFormat::Optimized|4095,KeyAssignment::Application);
    MemoryKeyFormat::validate(MemoryKeyFormat::Vendor|123,KeyAssignment::Provider);
    check_throws<std::invalid_argument>([] { MemoryKeyFormat::validate(uint64_t{1}<<56,KeyAssignment::Provider); });
    check_throws<std::invalid_argument>([] { MemoryKeyFormat::validate(uint64_t{1}<<48,KeyAssignment::Application); });
    check_throws<std::invalid_argument>([] { MemoryKeyFormat::validate(MemoryKeyFormat::Optimized|4096,KeyAssignment::Application); });
    check_throws<std::invalid_argument>([] { MemoryKeyFormat::validate(256,KeyAssignment::Application,1); });
    MemoryRegistry registry; registry.add_job(0); registry.add_job(1); registry.add_job(2);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Rkey|MemoryKeyFormat::IdempotentSafe;
    options.resource_index=17;
    const auto first=registry.register_region(1,7,64,7,options);
    const auto other_job=registry.register_region(2,7,64,7,options);
    const auto other_pid=registry.register_region(1,8,64,7,options);
    options.resource_index=18; const auto other_index=registry.register_region(1,7,64,7,options);
    CHECK(first.key==other_job.key && first.key==other_pid.key && first.key==other_index.key);
    CHECK(first.idempotent_safe && first.key==*options.requested_key);
    registry.write(1,7,first.key,0,{1},17); registry.write(2,7,first.key,0,{2},17);
    registry.write(1,8,first.key,0,{3},17); registry.write(1,7,first.key,0,{4},18);
    CHECK(registry.read(1,7,first.key,0,1,17)[0]==1 && registry.read(2,7,first.key,0,1,17)[0]==2);
    CHECK(registry.read(1,8,first.key,0,1,17)[0]==3 && registry.read(1,7,first.key,0,1,18)[0]==4);
    check_throws<MemoryAccessError>([&] { registry.write(1,7,first.key,0,{99},19); });
    check_throws<MemoryAccessError>([&] { registry.read(1,7,first.key,0,1); }); // Explicit scope is required when ambiguous.
    check_throws<std::invalid_argument>([&] { registry.deregister(first.key); });
    check_throws<std::invalid_argument>([&] { registry.register_region(1,7,64,7,options); });
    auto different_metadata=options; different_metadata.requested_key=*options.requested_key^MemoryKeyFormat::IdempotentSafe;
    check_throws<std::invalid_argument>([&] { registry.register_region(1,7,64,7,different_metadata); });
    CHECK(registry.deregister(other_index));
    CHECK(!registry.deregister(other_index));
    const auto replacement=registry.register_region(1,7,64,7,options);
    CHECK(!registry.deregister(other_index)); // Stale handle cannot revoke a reused numeric key.
    CHECK(registry.read(1,7,replacement.key,0,1,18)[0]==0);
    MemoryRegistry foreign; foreign.add_job(1);
    const auto foreign_region=foreign.register_region(1,7,64,7,options);
    CHECK(!foreign.deregister(first) && !registry.deregister(foreign_region));
    CHECK(registry.deregister(first));
    check_throws<MemoryAccessError>([&] { registry.read(1,7,first.key,0,1,17); });
    CHECK(registry.read(2,7,other_job.key,0,1,17)[0]==2);
    RegionOptions shared_options; shared_options.requested_key=42; shared_options.resource_index=17;
    shared_options.allow_any_job=true;
    const auto shared=registry.register_region(1,7,8,7,shared_options);
    shared_options.allow_any_job=false;
    registry.register_region(2,7,8,static_cast<uint8_t>(Access::Read),shared_options);
    // Exact Job authorization wins over the any-Job fallback. Denied access
    // must not retry lookup against a more permissive overlapping registration.
    check_throws<MemoryAccessError>([&] { registry.write(2,7,42,0,{99},17); });
    CHECK(registry.read(2,7,42,0,1,17)[0]==0);
    CHECK(shared.storage->allocated_pages()==0);
    registry.write(99,7,42,0,{8},17); // Explicit any-Job authorization ignores membership.
    CHECK(registry.read(99,7,42,0,1,17)[0]==8 && registry.read(2,7,42,0,1,17)[0]==0);
    RegionOptions flag_scope; flag_scope.requested_key=73|MemoryKeyFormat::IdempotentSafe; flag_scope.resource_index=17;
    const auto flagged=registry.register_region(1,7,8,7,flag_scope);
    flag_scope.requested_key=73; registry.register_region(2,7,8,7,flag_scope);
    check_throws<MemoryAccessError>([&] { registry.authorize(1,7,flagged.key,0,1,Access::Write,17,false); });
    check_throws<MemoryAccessError>([&] { registry.authorize(2,7,73,0,1,Access::Write,17,false); });
    registry.remove_job(1);
    CHECK(registry.read(2,7,other_job.key,0,1,17)[0]==2);
    options.requested_key=0; options.resource_index=0;
    const auto zero=registry.register_region(2,7,8,7,options);
    CHECK(zero.key==0); registry.write(2,7,0,0,{5},0); CHECK(registry.read(2,7,0,0,1,0)[0]==5);
    const auto zero_pid=registry.register_region(2,0,8,7,options);
    CHECK(zero_pid.pid_scope.has_value() && *zero_pid.pid_scope==0);
    registry.write(2,0,0,0,{6},0); CHECK(registry.read(2,0,0,0,1,0)[0]==6);
    check_throws<MemoryAccessError>([&] { registry.write(2,9,0,0,{99},0); });
    const auto zero_job=registry.register_region(0,0,8,7,options);
    registry.write(0,0,0,0,{7},0); CHECK(registry.read(0,0,zero_job.key,0,1,0)[0]==7);
    options.requested_key=MemoryKeyFormat::Optimized|1;
    // The existing resource_index0 cannot bind optimized MR index1.
    check_throws<std::invalid_argument>([&] { registry.register_region(2,7,8,7,options); });
}

void scoped_keys_cross_the_protocol() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    for (const auto job:{1u,2u}) { source.memory().add_job(job); target.memory().add_job(job); }
    target.resources().configure_resource(7,17,ResourceSpace::Rma);
    target.resources().configure_resource(7,18,ResourceSpace::Rma);
    target.resources().map_relative_pid(1,3,7); target.resources().map_relative_pid(2,3,7);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Rkey; options.resource_index=17;
    const auto first=target.memory().register_region(1,7,16,7,options);
    const auto second=target.memory().register_region(2,7,16,7,options);
    options.resource_index=18; const auto third=target.memory().register_region(1,7,16,7,options);
    const auto submit=[&](uint32_t job,uint16_t index,uint8_t value) {
        Operation write; write.type=OperationType::Write; write.peer=2; write.job=job;
        write.target_pid=3; write.target_resource=index; write.remote_key=first.key; write.payload={value};
        source.submit(write); loop.run(100000); Completion completion{};
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    };
    submit(1,17,1); submit(2,17,2); submit(1,18,3);
    CHECK(target.memory().read(1,7,first.key,0,1,17)[0]==1);
    CHECK(target.memory().read(2,7,second.key,0,1,17)[0]==2);
    CHECK(target.memory().read(1,7,third.key,0,1,18)[0]==3);
    Operation absolute; absolute.type=OperationType::Write; absolute.peer=2; absolute.job=1;
    absolute.relative_addressing=false; absolute.target_pid=7; absolute.target_resource=17;
    absolute.remote_key=first.key; absolute.payload={9};
    Completion completion{};
    source.submit(absolute); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.remote_code==0x1c); // Absolute selection cannot use Job to resolve ambiguity.
    CHECK(target.memory().deregister(second));
    absolute.job=2; source.submit(absolute); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.remote_code==0x17); // The remaining buffer still requires authorization.
    CHECK(target.memory().read(1,7,first.key,0,1,17)[0]==1);
    absolute.job=1; source.submit(absolute); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(target.memory().read(1,7,first.key,0,1,17)[0]==9);
    RegionOptions zero_scope; zero_scope.requested_key=0; zero_scope.resource_index=0;
    const auto zero_region=target.memory().register_region(1,0,8,3,zero_scope);
    target.resources().configure_resource(0,0,ResourceSpace::Rma);
    absolute.target_pid=0; absolute.target_resource=0; absolute.remote_key=0; absolute.payload={4};
    source.submit(absolute); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(target.memory().read(1,0,zero_region.key,0,1,0)[0]==4);
    source.memory().add_job(0); target.memory().add_job(0);
    zero_scope.resource_index=1;
    const auto zero_job=target.memory().register_region(0,1,8,3,zero_scope);
    absolute.job=0; absolute.relative_addressing=true; absolute.target_pid=1; absolute.target_resource=1;
    source.submit(absolute); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(target.memory().read(0,1,zero_job.key,0,1,1)[0]==4);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

void posting_keeps_its_registration() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    for (const auto job:{1u,2u}) { source.memory().add_job(job); target.memory().add_job(job); }
    target.resources().configure_resource(7,17,ResourceSpace::Send);
    target.resources().map_relative_pid(1,3,7); target.resources().map_relative_pid(2,3,7);
    RegionOptions options; options.requested_key=7; options.resource_index=17;
    const auto first=target.memory().register_region(1,7,16,3,options);
    const auto second=target.memory().register_region(2,7,16,3,options);
    target.post_receive(1,7,first.key,0,16,1,17);
    Operation send; send.type=OperationType::Send; send.peer=2; send.job=2; send.target_pid=7;
    send.target_resource=17; send.relative_addressing=false; send.payload={5};
    source.submit(send); loop.run(100000); Completion completion{};
    CHECK(source.poll_completion(completion) && completion.remote_code==0x17);
    CHECK(target.poll_completion(completion) && completion.context==1 && completion.remote_code==0x17);
    CHECK(first.storage->allocated_pages()==0 && second.storage->allocated_pages()==0);
    target.post_receive(1,7,first.key,0,16,2,17);
    CHECK(target.memory().deregister(first));
    const auto replacement=target.memory().register_region(1,7,16,3,options);
    send.job=1; send.relative_addressing=true; send.target_pid=3;
    source.submit(send); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.remote_code==0x1c);
    CHECK(target.poll_completion(completion) && completion.context==2 && completion.remote_code==0x1c);
    CHECK(replacement.storage->allocated_pages()==0 && second.storage->allocated_pages()==0);
    target.post_receive(1,7,replacement.key,0,16,3,17);
    send.type=OperationType::DatagramSend; send.relative_addressing=false; send.target_pid=7; send.job=2;
    source.submit(send); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::LocalSuccess);
    CHECK(!target.poll_completion(completion));
    send.job=1; source.submit(send); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::LocalSuccess);
    CHECK(target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==3);
    CHECK(target.memory().read(1,7,replacement.key,0,1,17)[0]==5 && second.storage->allocated_pages()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        key_format_and_scopes(); scoped_keys_cross_the_protocol(); posting_keeps_its_registration();
        std::cout<<"PASS: standard 48-bit RKEY, metadata bits, zero key/index, scoped key reuse and checked revocation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
