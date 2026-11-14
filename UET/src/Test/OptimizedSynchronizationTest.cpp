#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void group(RequestHeaderFormat format,pdc_mode mode,bool congestion,bool completing_first,
                  bool completing_atomic,bool failed_member) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    target.resources().configure_resource(1,3,ResourceSpace::Rma,7);
    target.resources().configure_resource(1,4,ResourceSpace::Rma,7);
    RegionOptions options; options.resource_index=3;
    options.requested_key=format==RequestHeaderFormat::Small?MemoryKeyFormat::Optimized|3:42;
    const auto region=target.memory().register_region(1,1,64,7,options);
    auto synchronization=source.begin_synchronized_group(2,1,3); CHECK(synchronization);
    Operation first; first.type=OperationType::SynchronizedWrite; first.header_format=format;
    first.peer=2; first.delivery_mode=mode; first.remote_key=region.key; first.target_resource=3;
    first.target_generation=7; first.remote_offset=16; first.payload.assign(8,0x31); first.synchronization=synchronization;
    if (failed_member) first.remote_key=format==RequestHeaderFormat::Small?MemoryKeyFormat::Optimized|4:UINT64_MAX;
    Operation second=first; second.remote_key=region.key; second.remote_offset=32; second.payload.assign(8,0x42);
    Operation completing=second; completing.remote_offset=0;
    if (completing_atomic) { completing.type=OperationType::SynchronizedAtomic; completing.payload={5,0,0,0,0,0,0,0}; }
    else { completing.payload.assign(8,0x53); completing.immediate_data=0; }
    size_t requests=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        if (frame.source!=1) return;
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type!=RUOD_req_header) return;
        CHECK(packet.SESpkt.bth_type==(format==RequestHeaderFormat::Small?Optimized_Header:Small_Message_RMA_Header));
        CHECK(packet.SESpkt.eth_type==Synchronized_Operation_Extension_Header || packet.SESpkt.eth_type==Synchronized_Atomic_Extension_Headers);
        ++requests;
    });
    if (completing_first) {
        source.submit(completing); loop.run_until(kMillisecond);
        Completion completion{}; CHECK(!target.poll_completion(completion));
        if (completing_atomic) {
            CHECK(!source.poll_completion(completion));
            CHECK(target.memory().read(1,1,region.key,0,8,3)==std::vector<uint8_t>(8));
        } else {
            // RUD WRITE placement cannot wait for other group members;
            // only the aggregate notification waits (§3.4.4.8/§3.4.9.6).
            CHECK(target.memory().read(1,1,region.key,0,8,3)==completing.payload);
        }
    }
    const auto first_identifier=source.submit(first); source.submit(second);
    if (!completing_first) source.submit(completing);
    loop.run_until(90*kMillisecond);
    Completion completion{}; size_t completions=0;
    while (source.poll_completion(completion)) {
        const auto expected=failed_member && completion.operation==first_identifier?CompletionStatus::RemoteError:CompletionStatus::Success;
        if (completion.status!=expected) throw std::runtime_error("optimized synchronization failed: format="+
            std::to_string(unsigned(format))+" mode="+std::to_string(mode)+" atomic="+std::to_string(completing_atomic)+
            " first="+std::to_string(completing_first)+" failed="+std::to_string(failed_member)+
            " status="+std::to_string(unsigned(completion.status))+" code="+std::to_string(completion.remote_code));
        ++completions;
    }
    CHECK(completions==3 && requests>=3);
    CHECK(target.memory().read(1,1,region.key,16,8,3)==std::vector<uint8_t>(8,failed_member?0:0x31));
    CHECK(target.memory().read(1,1,region.key,32,8,3)==second.payload);
    CHECK(target.memory().read(1,1,region.key,0,8,3)==completing.payload);
    if (!completing_atomic) CHECK(target.poll_completion(completion) && completion.receive &&
        completion.status==CompletionStatus::Success && completion.immediate_data==0 && completion.length==8);
    CHECK(!target.poll_completion(completion));
    CHECK(!source.pending() && !source.active_synchronized_source_groups() && !source.leased_message_ids() &&
        !target.retained_synchronized_groups() && !target.retained_synchronized_members() && !target.retained_synchronized_actions() &&
        !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

int main() {
    try {
        size_t scenarios=0;
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD})
            for (bool congestion:{false,true}) for (bool first:{false,true}) for (bool failed:{false,true}) {
                group(format,mode,congestion,first,true,failed); ++scenarios;
                if (format==RequestHeaderFormat::Medium) { group(format,mode,congestion,first,false,failed); ++scenarios; }
            }
        CHECK(scenarios==48);
        std::cout << "PASS48 optimized synchronization groups, atomic/WRITE completing actions, generations and failed members\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
