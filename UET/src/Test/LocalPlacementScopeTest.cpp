#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <algorithm>
#include <array>
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;

void registry_origin_checks() {
    MemoryRegistry registry; registry.add_job(1); registry.add_job(2);
    RegionOptions options; options.local_placement_only=true; options.requested_key=0x123456;
    options.resource_index=1;
    const auto local=registry.register_region(1,1,32,7,options);
    CHECK(registry.authorize_local(1,1,local.key,0,3,Access::Write,1).registration_id==local.registration_id);
    registry.write_registration(local,1,1,0,{1,2,3},1);
    for (const auto access:{Access::Read,Access::Write,Access::Atomic}) {
        check_throws<MemoryAccessError>([&] { registry.authorize(1,1,local.key,0,8,access,1,true); });
        check_throws<MemoryAccessError>([&] { registry.authorize(1,1,local.key,0,8,access,1,false); });
    }
    check_throws<MemoryAccessError>([&] { registry.write(1,1,local.key,0,{99}); });
    check_throws<MemoryAccessError>([&] { registry.read(1,1,local.key,0,8); });
    check_throws<MemoryAccessError>([&] { registry.atomic(1,1,local.key,0,Atomic64::Add,1); });
    check_throws<MemoryAccessError>([&] { registry.authorize_local(2,1,local.key,0,3,Access::Write,1); });
    check_throws<MemoryAccessError>([&] { registry.authorize_local(1,1,local.key,31,3,Access::Write,1); });
    std::array<uint8_t,3> bytes{}; local.storage->read(0,bytes.data(),bytes.size()); CHECK((bytes==std::array<uint8_t,3>{{1,2,3}}));
    CHECK(registry.deregister(local));
    const auto replacement=registry.register_region(1,1,32,7,options);
    check_throws<MemoryAccessError>([&] { registry.write_registration(local,1,1,0,{99},1); });
    replacement.storage->read(0,bytes.data(),bytes.size()); CHECK((bytes==std::array<uint8_t,3>{{0,0,0}}));
}

void protocol_placement(pdc_mode mode,bool congestion) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1132);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions local_only; local_only.local_placement_only=true;
    std::array<uint8_t,64> result_bytes{},receive_bytes{},remote_bytes{};
    const auto local_result=source.memory().register_buffer(1,1,result_bytes.data(),result_bytes.size(),7,local_only);
    const auto local_receive=target.memory().register_buffer(1,1,receive_bytes.data(),receive_bytes.size(),7,local_only);
    const auto public_remote=target.memory().register_buffer(1,1,remote_bytes.data(),remote_bytes.size(),7);
    for (size_t byte=0;byte<24;++byte) remote_bytes[byte]=static_cast<uint8_t>(byte+1);
    remote_bytes[32]=3;
    const auto run=[&](Operation operation,CompletionStatus expected,uint8_t code=1) {
        operation.peer=2; operation.delivery_mode=mode;
        const auto submitted=source.submit(std::move(operation)); loop.run(100000);
        Completion completion{}; CHECK(source.poll_completion(completion) && completion.operation==submitted &&
            completion.status==expected && completion.remote_code==code && !source.poll_completion(completion));
        CHECK(source.leased_message_ids()==0);
    };
    // The same known key and R/W/Atomic rights cannot authorize direct RMA to
    // a local placement region. Check both relative and absolute addressing.
    for (const bool relative:{true,false}) {
        Operation operation; operation.relative_addressing=relative; operation.remote_key=local_receive.key;
        operation.type=OperationType::Write; operation.payload={99}; run(operation,CompletionStatus::RemoteError,0x18);
        operation.type=OperationType::Atomic; operation.payload={1,0,0,0,0,0,0,0}; run(operation,CompletionStatus::RemoteError,0x18);
        operation.type=OperationType::FetchingAtomic; operation.atomic_result=AtomicResultBuffer{local_result.key,0,8,1,1};
        run(operation,CompletionStatus::RemoteError,0x18);
        operation=Operation{}; operation.relative_addressing=relative; operation.remote_key=local_receive.key;
        operation.type=OperationType::Read; operation.read_length=8; operation.read_result=ReadResultBuffer{local_result.key,0,8,1,1};
        run(operation,CompletionStatus::RemoteError,0x18);
        CHECK(std::all_of(receive_bytes.begin(),receive_bytes.end(),[](auto byte) { return byte==0; }));
    }
    // A local application explicitly supplies these placements. READ17 uses
    // reverse PDS Request; READ8 uses data ACK, and fetching uses cached ACK.
    Operation read; read.type=OperationType::Read; read.remote_key=public_remote.key; read.read_length=17;
    read.read_result=ReadResultBuffer{local_result.key,0,17,1,1}; run(read,CompletionStatus::Success);
    CHECK(std::equal(remote_bytes.begin(),remote_bytes.begin()+17,result_bytes.begin()));
    read.read_length=8; read.remote_offset=16; read.read_result=ReadResultBuffer{local_result.key,20,8,1,1}; run(read,CompletionStatus::Success);
    CHECK(std::equal(remote_bytes.begin()+16,remote_bytes.begin()+24,result_bytes.begin()+20));
    Operation fetch; fetch.type=OperationType::FetchingAtomic; fetch.remote_key=public_remote.key; fetch.remote_offset=32;
    fetch.payload={1,0,0,0,0,0,0,0}; fetch.atomic_result=AtomicResultBuffer{local_result.key,40,8,1,1}; run(fetch,CompletionStatus::Success);
    CHECK(result_bytes[40]==3 && remote_bytes[32]==4);
    target.post_receive(1,1,local_receive.key,0,8,77);
    Operation send; send.type=OperationType::Send; send.payload={'s','e','s'}; run(send,CompletionStatus::Success);
    Completion received{}; CHECK(target.poll_completion(received) && received.receive && received.context==77 && received.length==3);
    CHECK(receive_bytes[0]=='s' && receive_bytes[1]=='e' && receive_bytes[2]=='s');
    target.post_receive(1,1,local_receive.key,8,8,78);
    send.type=OperationType::DatagramSend;
    run(send,CompletionStatus::LocalSuccess,0);
    CHECK(target.poll_completion(received) && received.receive && received.context==78 && received.length==3);
    CHECK(receive_bytes[8]=='s' && !target.poll_completion(received));
    CHECK(target.retained_receive_messages()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        registry_origin_checks();
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true}) protocol_placement(mode,congestion);
        std::cout<<"PASS local placement authority, direct RMA denial, posted SEND/UUD, both READ carriers and atomic results\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
