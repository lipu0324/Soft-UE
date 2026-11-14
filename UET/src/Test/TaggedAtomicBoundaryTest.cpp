#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

enum class Rejection { MissingAtomicRight, Truncated, Unaligned, ReusedRegistration, MissingMatch };

static void rejected(bool fetching,RequestHeaderFormat format,pdc_mode mode,bool congestion,Rejection reason) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options; options.local_placement_only=true; options.requested_key=42;
    const auto registration=target.memory().register_region(1,1,32,reason==Rejection::MissingAtomicRight?3:7,options);
    target.post_tagged_receive(1,1,registration.key,reason==Rejection::Unaligned?1:0,
        reason==Rejection::Truncated?7:16,{reason==Rejection::MissingMatch?78u:77u,0,1},99);
    std::optional<Region> replacement;
    if (reason==Rejection::ReusedRegistration) {
        CHECK(target.memory().deregister(registration));
        replacement=target.memory().register_region(1,1,32,7,options);
    }
    const auto local=source.memory().register_region(1,1,8,7);
    Operation operation; operation.type=fetching?OperationType::TaggedFetchingAtomic:OperationType::TaggedAtomic;
    operation.peer=2; operation.delivery_mode=mode; operation.header_format=format; operation.tag=77; operation.payload.assign(8,1);
    if (fetching) operation.atomic_result=AtomicResultBuffer{local.key,0,8,1,1};
    source.submit(operation);
    if (reason==Rejection::MissingMatch && mode==ROD) {
        loop.run_until(10000); CHECK(target.unexpected_bytes()==8); target.close();
    }
    loop.run_until(90*kMillisecond);
    const auto expected=reason==Rejection::MissingAtomicRight?SemanticReturnCode::OperationViolation:
        reason==Rejection::Truncated?SemanticReturnCode::UnsupportedSize:
        reason==Rejection::Unaligned?SemanticReturnCode::AtomicUnaligned:
        reason==Rejection::ReusedRegistration?SemanticReturnCode::BadMemoryKey:
        mode==ROD?SemanticReturnCode::Undeliverable:SemanticReturnCode::NoMatch;
    Completion completion{};
    if (!source.poll_completion(completion) || completion.status!=CompletionStatus::RemoteError ||
        completion.remote_code!=static_cast<uint8_t>(expected))
        throw std::runtime_error("tagged atomic rejection mismatch: fetching="+std::to_string(fetching)+" format="+
            std::to_string(unsigned(format))+" mode="+std::to_string(mode)+" reason="+std::to_string(unsigned(reason))+
            " code="+std::to_string(completion.remote_code));
    CHECK(!source.poll_completion(completion));
    if (reason!=Rejection::MissingMatch) {
        CHECK(target.poll_completion(completion) && completion.receive && completion.context==99 && completion.tag==77 &&
            completion.length==0 && completion.remote_code==static_cast<uint8_t>(expected));
        CHECK(completion.status==(reason==Rejection::Truncated?CompletionStatus::Truncated:CompletionStatus::RemoteError));
    }
    CHECK(!target.poll_completion(completion));
    std::vector<uint8_t> actual(32); registration.storage->read(0,actual.data(),actual.size()); CHECK(actual==std::vector<uint8_t>(32,0));
    if (replacement) { replacement->storage->read(0,actual.data(),actual.size()); CHECK(actual==std::vector<uint8_t>(32,0)); }
    CHECK(source.memory().read(1,1,local.key,0,8)==std::vector<uint8_t>(8,0));
    CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages() && !target.unexpected_bytes());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

class ZeroAtomicStorage final : public MemoryStorage {
public:
    uint64_t size() const override { return 0; }
    size_t allocated_pages() const override { return 0; }
    void read(uint64_t offset,uint8_t*,size_t length) const override { CHECK(!offset && !length); ++reads; }
    void write(uint64_t,const uint8_t*,size_t) override { ++writes; }
    mutable size_t reads=0;
    size_t writes=0;
};

static void zero_operation(bool fetching,bool get,pdc_mode mode,bool late) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    auto storage=std::make_shared<ZeroAtomicStorage>();
    RegionOptions options; options.local_placement_only=true;
    const auto region=target.memory().register_storage(1,1,storage,7,options);
    const auto post=[&] { target.post_tagged_receive(1,1,region.key,0,0,{77,0,1},99); };
    if (!late) post();
    Operation operation; operation.type=fetching?OperationType::TaggedFetchingAtomic:OperationType::TaggedAtomic;
    operation.peer=2; operation.delivery_mode=mode; operation.tag=77; operation.zero_length_atomic=true;
    operation.atomic_operation=get?IntegerAtomicOperation::Read:IntegerAtomicOperation::Write;
    source.submit(operation);
    if (late) { loop.run_until(10000); CHECK(target.retained_receive_messages()==1); post(); }
    loop.run_until(90*kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.length==0);
    CHECK(target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==99 &&
        completion.length==0 && completion.tag==77);
    CHECK(storage->reads==(get?1u:0u) && !storage->writes);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages() && !target.unexpected_bytes());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

static void unsupported_format_has_no_transport_state(bool fetching,unsigned selection) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1); PdsHost host(1,loop,trace,port);
    Endpoint source(1,host,loop,trace,64); source.memory().add_job(1);
    Operation operation; operation.type=fetching?OperationType::TaggedFetchingAtomic:OperationType::TaggedAtomic;
    operation.peer=2; operation.tag=77; operation.payload.assign(8,1);
    if (selection==0) operation.header_format=RequestHeaderFormat::Small;
    if (selection==1) { operation.header_format=RequestHeaderFormat::Medium; operation.remote_offset=8; }
    if (selection==2) operation.delivery_mode=RUDI;
    source.submit(operation);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Unsupported);
    CHECK(!source.pending() && !source.leased_message_ids() && !host.manager().getPDSStatus().open_cnt);
    source.close(); host.close(); CHECK(!loop.pending());
}

int main() {
    try {
        for (bool fetching:{false,true}) for (auto format:{RequestHeaderFormat::Standard,RequestHeaderFormat::Medium})
            for (auto mode:{RUD,ROD}) for (bool congestion:{false,true})
                for (auto reason:{Rejection::MissingAtomicRight,Rejection::Truncated,Rejection::Unaligned,
                                  Rejection::ReusedRegistration,Rejection::MissingMatch}) rejected(fetching,format,mode,congestion,reason);
        for (auto mode:{RUD,ROD}) for (bool late:{false,true}) {
            if (late && mode!=ROD) continue;
            zero_operation(false,false,mode,late); zero_operation(true,false,mode,late); zero_operation(true,true,mode,late);
        }
        for (bool fetching:{false,true}) for (unsigned selection=0;selection<3;++selection)
            unsupported_format_has_no_transport_state(fetching,selection);
        std::cout << "PASS80 tagged atomic rejection scenes,9 zero-byte boundaries and6 unsupported-format admissions\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
