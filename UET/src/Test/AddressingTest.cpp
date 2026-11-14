#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;

int main() {
    try {
        EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
        auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
        Endpoint source(1,source_host,loop,trace,17),target(2,target_host,loop,trace,17);
        source.memory().add_job(1); source.memory().add_job(99); target.memory().add_job(1);
        target.resources().map_relative_pid(1,7,42);
        target.resources().configure_resource(42,17,ResourceSpace::Rma,5);
        target.resources().configure_resource(42,18,ResourceSpace::Rma);
        target.resources().configure_resource(42,0,ResourceSpace::Rma);
        RegionOptions options; options.allow_any_job=true; options.resource_index=17;
        const auto shared=target.memory().register_region(1,42,128,7,options);
        options.allow_any_job=false;
        const auto private_region=target.memory().register_region(1,42,128,7,options);
        Operation write; write.type=OperationType::Write; write.peer=2;
        write.target_pid=7; write.target_resource=17; write.target_generation=5;
        write.remote_key=shared.key; write.payload.assign(33,0xa5);
        auto submit=[&](const Operation& operation,CompletionStatus expected,uint8_t code,uint8_t generation=0) {
            const auto id=source.submit(operation); loop.run_until(loop.now()+kMillisecond);
            Completion completion{};
            CHECK(source.poll_completion(completion) && completion.operation==id);
            CHECK(completion.status==expected && completion.remote_code==code);
            CHECK(completion.remote_generation==generation);
            CHECK(!source.poll_completion(completion));
        };
        submit(write,CompletionStatus::Success,1,5); // Relative job PID 7 maps to absolute PID 42.
        CHECK(target.memory().read(1,42,shared.key,0,33)==write.payload);
        write.relative_addressing=false; write.target_pid=42; write.remote_offset=40;
        submit(write,CompletionStatus::Success,1,5);
        CHECK(target.memory().read(1,42,shared.key,40,33)==write.payload);

        // Absolute lookup needs no target job mapping. This MR explicitly
        // authorizes any JobID; an exact-job MR still rejects the same request.
        write.job=99; write.remote_offset=80; write.payload={9};
        submit(write,CompletionStatus::Success,1,5);
        write.remote_key=private_region.key;
        submit(write,CompletionStatus::RemoteError,0x17,5);
        CHECK(target.memory().read(1,42,private_region.key,80,1)==std::vector<uint8_t>({0}));
        write.relative_addressing=true; write.target_pid=7; write.remote_key=shared.key;
        submit(write,CompletionStatus::RemoteError,0x1b,5); // Job 99 has no relative context at target.

        write.relative_addressing=false; write.target_pid=42; write.job=1;
        write.target_resource=18; write.target_generation=0;
        submit(write,CompletionStatus::RemoteError,0x1c); // Key is bound to index 17.
        write.target_resource=0;
        submit(write,CompletionStatus::RemoteError,0x1c); // Index zero is not a wildcard.
        options.resource_index=0;
        const auto index_zero=target.memory().register_region(1,42,128,7,options);
        write.remote_key=index_zero.key;
        submit(write,CompletionStatus::Success,1);

        write.remote_key=shared.key; write.target_resource=17;
        submit(write,CompletionStatus::RemoteError,0x02,5); // Return the actual generation on mismatch.
        target.resources().configure_resource(42,17,ResourceSpace::Rma,5,false);
        submit(write,CompletionStatus::RemoteError,0x04,5);
        write.target_generation=5;
        submit(write,CompletionStatus::RemoteError,0x03,5);
        target.resources().configure_resource(42,17,ResourceSpace::Rma,6,true);
        submit(write,CompletionStatus::RemoteError,0x02,6);
        write.target_generation=6;
        submit(write,CompletionStatus::Success,1,6);

        // Numeric index 17 in SEND has its own generation and FIFO queue.
        target.resources().configure_resource(42,17,ResourceSpace::Send,8);
        target.post_receive(1,42,shared.key,96,4,123,17);
        Operation send; send.peer=2; send.target_pid=7; send.target_resource=17;
        send.target_generation=8; send.payload={1,2,3};
        submit(send,CompletionStatus::Success,1,8);
        Completion receive{};
        CHECK(target.poll_completion(receive) && receive.receive && receive.context==123);
        CHECK(target.memory().read(1,42,shared.key,96,3)==send.payload);
        target.post_receive(1,42,shared.key,104,4,124,17);
        send.type=OperationType::DatagramSend; send.relative_addressing=false;
        send.target_pid=42; send.job=99;
        submit(send,CompletionStatus::LocalSuccess,0);
        CHECK(target.poll_completion(receive) && receive.receive && receive.context==124);
        CHECK(target.memory().read(1,42,shared.key,104,3)==send.payload);

        CHECK(target.memory().deregister(shared.key));
        submit(write,CompletionStatus::RemoteError,0x1c,6);
        source.close(); target.close(); source_host.close(); target_host.close();
        CHECK(loop.pending()==0);
        std::cout<<"PASS: relative/absolute PID, independent resource spaces, generation/disabled errors and MR scope\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
