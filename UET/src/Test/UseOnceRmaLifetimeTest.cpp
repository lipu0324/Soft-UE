#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

enum class GrantEnd { Completed, SourceClosed, TargetClosed, Revoked };

// Separate FEPs share one registration domain. Limit each real PDS to one
// packet in flight so the first WRITE remains partial while its rival arrives.
static void shared_domain(pdc_mode mode,bool congestion,GrantEnd ending) {
    constexpr uint32_t length=4096,mtu=64;
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& first_port=fabric.add_host(1); auto& first_target_port=fabric.add_host(2);
    auto& rival_port=fabric.add_host(3); auto& rival_target_port=fabric.add_host(4);
    LinkConfig link; link.delay_ns=100000;
    fabric.add_link(1,2,link); fabric.add_link(2,1,link);
    fabric.add_link(3,4,link); fabric.add_link(4,3,link);
    PdsHost first_host(1,loop,trace,first_port),first_target_host(2,loop,trace,first_target_port);
    PdsHost rival_host(3,loop,trace,rival_port),rival_target_host(4,loop,trace,rival_target_port);
    first_host.services().psn_ranges.local_packet_capacity=1;
    rival_host.services().psn_ranges.local_packet_capacity=1;
    if (congestion) {
        first_host.enable_nscc({}); first_target_host.enable_nscc({});
        rival_host.enable_nscc({}); rival_target_host.enable_nscc({});
    }
    MemoryRegistry domain; domain.add_job(1);
    Endpoint first(1,first_host,loop,trace,mtu,100*kMillisecond,nullptr,1);
    Endpoint target(2,first_target_host,loop,trace,mtu,100*kMillisecond,&domain);
    Endpoint rival(3,rival_host,loop,trace,mtu,100*kMillisecond,nullptr,1);
    Endpoint other_target(4,rival_target_host,loop,trace,mtu,100*kMillisecond,&domain);
    first.memory().add_job(1); rival.memory().add_job(1);
    RegionOptions options; options.use_once=true; options.requested_key=42;
    const auto registration=domain.register_region(1,1,length,7,options);
    Operation write; write.type=OperationType::Write; write.peer=2; write.delivery_mode=mode;
    write.remote_key=registration.key; write.payload.assign(length,0x71);
    first.submit(write); loop.run_until(150000);
    std::vector<uint8_t> partial(length); registration.storage->read(0,partial.data(),partial.size());
    CHECK(std::count(partial.begin(),partial.end(),0x71)==mtu && domain.retained_use_once_claims()==1);
    Operation competing=write; competing.peer=4; competing.remote_offset=length-8; competing.payload.assign(8,0x99);
    rival.submit(competing); loop.run_until(kMillisecond);
    Completion completion{};
    CHECK(rival.poll_completion(completion) && completion.status==CompletionStatus::RemoteError &&
        completion.remote_code==static_cast<uint8_t>(SemanticReturnCode::BadMemoryKey));
    CHECK(domain.retained_use_once_claims()==1 && !first.poll_completion(completion));
    std::optional<Region> replacement;
    if (ending==GrantEnd::SourceClosed) first.close();
    if (ending==GrantEnd::TargetClosed) target.close();
    if (ending==GrantEnd::Revoked) CHECK(domain.deregister(registration));
    if (ending==GrantEnd::TargetClosed || ending==GrantEnd::Revoked) {
        CHECK(domain.retained_use_once_claims()==0);
        // A persistent replacement makes an accidental old-message rebind
        // visible. Old Clear must not revoke this new registration either.
        options.use_once=false; replacement=domain.register_region(1,1,length,7,options);
        competing.remote_offset=0; rival.submit(competing);
    }
    loop.run_until(90*kMillisecond);
    CHECK(first.poll_completion(completion));
    const auto expected=ending==GrantEnd::Completed?CompletionStatus::Success:
        ending==GrantEnd::SourceClosed?CompletionStatus::Cancelled:CompletionStatus::RemoteError;
    CHECK(completion.status==expected && !first.poll_completion(completion));
    CHECK(!domain.retained_use_once_claims() && !target.retained_receive_messages() && !other_target.retained_receive_messages());
    std::vector<uint8_t> actual(length); registration.storage->read(0,actual.data(),actual.size());
    if (ending==GrantEnd::Completed) CHECK(actual==std::vector<uint8_t>(length,0x71));
    else CHECK(std::count(actual.begin(),actual.end(),0x71)<length);
    CHECK(std::find(actual.begin(),actual.end(),0x99)==actual.end());
    if (replacement) {
        CHECK(rival.poll_completion(completion) && completion.status==CompletionStatus::Success);
        auto contents=domain.read(1,1,replacement->key,0,length,1);
        // Only the rival's8 bytes may change.
        CHECK(std::count(contents.begin(),contents.end(),0x99)==8 &&
            std::count(contents.begin(),contents.end(),0)==length-8);
        CHECK(domain.authorize_registration(*replacement,1,1,0,length,Access::Write).registration_id==replacement->registration_id);
    }
    CHECK(!rival.poll_completion(completion));
    first.close(); target.close(); rival.close(); other_target.close();
    first_host.close(); first_target_host.close(); rival_host.close(); rival_target_host.close(); CHECK(!loop.pending());
}

int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true})
            for (auto ending:{GrantEnd::Completed,GrantEnd::SourceClosed,GrantEnd::TargetClosed,GrantEnd::Revoked})
                shared_domain(mode,congestion,ending);
        std::cout << "PASS16 shared-domain use-once exclusion, partial WRITE, close, revocation and numeric-key replacement\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
