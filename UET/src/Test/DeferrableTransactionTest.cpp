#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// Both production target policies use the original SES/PDS path. Independent
// RTR suffix/identity policies and lifecycle faults are covered by the sibling
// DeferrableRestart/DeferrableFault tests.
void expected_and_retry(pdc_mode mode,bool tagged,bool late,bool congestion,uint32_t length,bool capture=false) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1132);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,1024),target(2,target_host,loop,trace,1024);
    source.memory().add_job(1); target.memory().add_job(1);
    if (capture) target.enable_deferrable_capture();
    const auto region=target.memory().register_region(1,1,length+8,7);
    const auto post=[&] {
        if (tagged) target.post_tagged_receive(1,1,region.key,4,length,{UINT64_MAX,0,uint32_t{0}},77);
        else target.post_receive(1,1,region.key,4,length,77,1,uint32_t{0});
    };
    if (late) loop.after(5*kMillisecond,post); else post();
    Operation operation;
    operation.type=tagged?OperationType::DeferrableTaggedSend:OperationType::DeferrableSend;
    operation.peer=2; operation.delivery_mode=mode; operation.initiator_id=0;
    operation.tag=UINT64_MAX; operation.context=99; operation.immediate_data=42;
    operation.payload.resize(length);
    for (uint32_t byte=0;byte<length;++byte) operation.payload[byte]=static_cast<uint8_t>(byte*7+3);
    const auto submitted=source.submit(operation); loop.run(1000000);
    Completion completion{};
    if (source.poll_completion(completion)) {
        if (completion.status!=CompletionStatus::Success)
            std::cerr<<"deferrable status="<<unsigned(completion.status)<<" code="<<unsigned(completion.remote_code)
                <<" mode="<<mode<<" tagged="<<tagged<<" late="<<late<<" length="<<length<<'\n';
    } else throw std::runtime_error("missing deferrable source completion");
    CHECK(completion.operation==submitted && completion.context==99 && completion.status==CompletionStatus::Success &&
        completion.length==length && !source.poll_completion(completion));
    CHECK(target.poll_completion(completion) && completion.context==77 && completion.receive &&
        completion.status==CompletionStatus::Success && completion.length==length && completion.immediate_data==42);
    CHECK(completion.tag==(tagged?std::optional<uint64_t>{UINT64_MAX}:std::nullopt));
    CHECK(!target.poll_completion(completion) && target.memory().read(1,1,region.key,4,length)==operation.payload);
    CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages() && !target.unexpected_bytes() && !target.captured_deferrable_headers());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (const auto mode:{RUD,ROD}) for (const bool tagged:{false,true}) for (const bool late:{false,true})
            for (const bool congestion:{false,true}) for (const uint32_t length:{0,1,1024,1025,4097})
                for (const bool capture:{false,true}) expected_and_retry(mode,tagged,late,congestion,length,capture);
        std::cout<<"PASS deferrable transactions: expected/retry/capture, SEND/tagged, RUD/ROD and NSCC\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
