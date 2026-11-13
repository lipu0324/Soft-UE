#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// Exercise the original PDS in both directions. An early completing WRITE
// places payload before its notification. A completing atomic submitted first
// waits locally for the writes; SynchronizedTargetTest independently sends an
// atomic first on the wire to exercise the target's actual barrier.
void aggregate_action(pdc_mode mode,bool congestion,bool atomic,bool completing_first,bool failed_member,size_t payload_mtu=16) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,128);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,payload_mtu),target(2,target_host,loop,trace,payload_mtu);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto destination=target.memory().register_region(1,1,128,7);
    const auto group=source.begin_synchronized_group(2,1,3);
    CHECK(group && group->wire_identifier()==0 && group->message_count()==3);
    Operation first; first.type=OperationType::SynchronizedWrite; first.peer=2; first.delivery_mode=mode;
    first.remote_key=failed_member?UINT64_MAX:destination.key; first.payload.assign(37,0x31); first.synchronization=group;
    Operation second=first; second.remote_key=destination.key; second.remote_offset=40; second.payload.assign(19,0x42);
    Operation completing=first; completing.remote_key=destination.key; completing.remote_offset=72;
    if (atomic) {
        completing.type=OperationType::SynchronizedAtomic;
        completing.atomic_datatype=payload_mtu<8?IntegerAtomicDatatype::Uint8:IntegerAtomicDatatype::Uint64;
        completing.payload={5,0,0,0,0,0,0,0};
    } else { completing.payload.assign(7,0x53); completing.immediate_data=0; }
    uint64_t completing_operation=0;
    if (completing_first) {
        completing_operation=source.submit(completing); loop.run_until(kMillisecond);
        Completion result{}; CHECK(!target.poll_completion(result));
        if (atomic) {
            CHECK(target.memory().read(1,1,destination.key,72,8)==std::vector<uint8_t>(8));
            CHECK(!source.poll_completion(result));
        } else CHECK(target.memory().read(1,1,destination.key,72,7)==std::vector<uint8_t>(7,0x53));
    }
    const auto first_operation=source.submit(first),second_operation=source.submit(second);
    if (!completing_first) completing_operation=source.submit(completing);
    loop.run(300000);
    CHECK(!source.pending() && !source.active_synchronized_source_groups());
    Completion result{}; size_t completions=0; std::set<uint64_t> identifiers;
    while (source.poll_completion(result)) {
        CHECK(!result.receive && identifiers.insert(result.operation).second);
        CHECK(result.operation==first_operation || result.operation==second_operation || result.operation==completing_operation);
        if (result.status!=(failed_member && result.operation==first_operation?CompletionStatus::RemoteError:CompletionStatus::Success))
            std::cerr<<"unexpected operation="<<result.operation<<" status="<<static_cast<int>(result.status)<<" code="<<unsigned(result.remote_code)<<'\n';
        CHECK(result.status==(failed_member && result.operation==first_operation?CompletionStatus::RemoteError:CompletionStatus::Success));
        if (failed_member && result.operation==first_operation) CHECK(result.remote_code==static_cast<uint8_t>(SemanticReturnCode::BadMemoryKey));
        ++completions;
    }
    CHECK(completions==3);
    CHECK(target.memory().read(1,1,destination.key,0,37)==std::vector<uint8_t>(37,failed_member?0:0x31));
    CHECK(target.memory().read(1,1,destination.key,40,19)==second.payload);
    CHECK(target.memory().read(1,1,destination.key,72,completing.payload.size())==completing.payload);
    if (!atomic) {
        CHECK(target.poll_completion(result) && result.receive && result.status==CompletionStatus::Success &&
            result.length==7 && result.immediate_data==0);
    }
    CHECK(!target.poll_completion(result));
    CHECK(!target.retained_synchronized_groups() && !target.retained_synchronized_members() &&
        !source.retained_receive_messages() && !target.retained_receive_messages() && !source.leased_message_ids());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) for (bool atomic:{false,true})
            for (bool first:{false,true}) for (bool failed:{false,true}) {
                try { aggregate_action(mode,congestion,atomic,first,failed); }
                catch (...) { std::cerr<<"mode="<<mode<<" nscc="<<congestion<<" atomic="<<atomic<<" first="<<first<<" failed="<<failed<<'\n'; throw; }
            }
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) for (size_t mtu:{1,2}) {
            try { aggregate_action(mode,congestion,true,true,false,mtu); }
            catch (...) { std::cerr<<"fragmented mode="<<mode<<" nscc="<<congestion<<" mtu="<<mtu<<'\n'; throw; }
        }
        std::cout<<"PASS40 real-PDS synchronized WRITE/atomic actions, completing order, fragmented <=8B operands, failed members and NSCC\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
