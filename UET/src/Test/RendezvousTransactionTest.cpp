#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

void native_transaction(bool tagged,pdc_mode mode,bool standalone,bool late,bool congestion,uint32_t length,uint32_t eager) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(standalone?0:16); target_host.configure_read_ack_data(standalone?0:16);
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    CHECK(source.capabilities().rendezvous_send && source.capabilities().rendezvous_tagged_send &&
        !source.capabilities().ai_base && !source.capabilities().ai_full &&
        !source.capabilities().hpc && !source.capabilities().unified_local);
    source.memory().add_job(1); target.memory().add_job(1);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,148);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    auto source_storage=std::make_shared<SparseMemory>(uint64_t{length}+8);
    std::vector<uint8_t> original(length);
    for (uint32_t byte=0;byte<length;++byte) original[byte]=static_cast<uint8_t>(byte*7+3);
    source_storage->write(4,original.data(),original.size());
    RegionOptions options; options.requested_key=0x1234;
    const auto source_region=source.memory().register_storage(1,1,source_storage,1,options);
    const auto destination=target.memory().register_region(1,1,uint64_t{length}+8,7);
    const auto post=[&] {
        if (tagged) target.post_tagged_receive(1,1,destination.key,4,length,{UINT64_MAX,0,uint32_t{0}},77);
        else target.post_receive(1,1,destination.key,4,length,77,1,uint32_t{0});
    };
    if (late) loop.after(5*kMillisecond,post); else post();
    Operation operation; operation.type=tagged?OperationType::RendezvousTaggedSend:OperationType::RendezvousSend;
    operation.peer=2; operation.delivery_mode=mode; operation.initiator_id=0; operation.tag=UINT64_MAX;
    operation.context=99; operation.immediate_data=42;
    operation.rendezvous_source=RendezvousBuffer{source_region.key,4,length,1,1,0}; operation.rendezvous_eager_length=eager;
    const auto submitted=source.submit(operation); loop.run(1000000);
    Completion completion{};
    if (!source.poll_completion(completion)) throw std::runtime_error("missing native rendezvous source completion");
    if (completion.status!=CompletionStatus::Success)
        std::cerr<<"source status="<<unsigned(completion.status)<<" code="<<unsigned(completion.remote_code)
            <<" tagged="<<tagged<<" mode="<<mode<<" standalone="<<standalone<<" late="<<late
            <<" NSCC="<<congestion<<" length="<<length<<" eager="<<eager<<'\n';
    CHECK(completion.operation==submitted && completion.context==99 && completion.status==CompletionStatus::Success &&
        completion.length==length && !source.poll_completion(completion));
    CHECK(target.poll_completion(completion) && completion.receive && completion.context==77 &&
        completion.status==CompletionStatus::Success && completion.length==length && completion.immediate_data==42);
    CHECK(completion.tag==(tagged?std::optional<uint64_t>{UINT64_MAX}:std::nullopt) && !target.poll_completion(completion));
    CHECK(target.memory().read(1,1,destination.key,4,length)==original);
    CHECK(!source.pending() && !target.pending() && !source.leased_message_ids() && !target.leased_message_ids() &&
        !source.retained_receive_messages() && !target.retained_receive_messages() &&
        !source.retained_read_packets() && !target.retained_read_packets() &&
        !source.pending_read_returns() && !target.pending_read_returns());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (bool tagged:{false,true}) for (auto mode:{RUD,ROD}) for (bool standalone:{false,true})
            for (bool late:{false,true}) for (bool congestion:{false,true}) for (uint32_t length:{0,1,16,17,73,4097}) {
                const std::set<uint32_t> eager_lengths={0,std::min<uint32_t>(16,length),length};
                for (const auto eager:eager_lengths) native_transaction(tagged,mode,standalone,late,congestion,length,eager);
            }
        std::cout<<"PASS native rendezvous SEND/tagged, expected/late, zero/MTU/multifragment, both READ carriers and NSCC\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
