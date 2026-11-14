#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void authority(pdc_mode mode,unsigned scenario) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); source.memory().add_job(2);
    target.memory().add_job(1); if (scenario!=1) target.memory().add_job(2);
    target.resources().configure_resource(1,3,ResourceSpace::Rma);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Optimized|3; options.idempotent_safe=true;
    auto permissions=uint8_t{7};
    if (scenario==5) permissions=static_cast<uint8_t>(Access::Write);
    if (scenario==6) options.local_placement_only=true;
    if (scenario==7) options.rendezvous_source_only=true;
    if (scenario==11) options.allow_any_job=true;
    const auto registration_job=scenario==10 || scenario==11?2u:1u;
    const auto region=target.memory().register_storage(registration_job,1,std::make_shared<SparseMemory>(16),permissions,options);
    Operation operation; operation.type=OperationType::Read; operation.header_format=RequestHeaderFormat::Small;
    operation.delivery_mode=mode; operation.peer=2; operation.remote_key=region.key; operation.payload={7};
    auto expected=SemanticReturnCode::Ok;
    switch (scenario) {
    case 0: operation.job=2; expected=SemanticReturnCode::PermissionViolation; break;
    case 1: operation.job=2; expected=SemanticReturnCode::BadJob; break;
    case 2: operation.target_pid=2; target.resources().map_relative_pid(1,2,2);
        target.resources().configure_resource(2,3,ResourceSpace::Rma); expected=SemanticReturnCode::PermissionViolation; break;
    case 3: operation.remote_key=MemoryKeyFormat::Optimized|4; target.resources().configure_resource(1,4,ResourceSpace::Rma);
        expected=SemanticReturnCode::BadMemoryKey; break;
    case 4: operation.remote_offset=16; expected=SemanticReturnCode::BadAddress; break;
    case 5: case 6: case 7: expected=SemanticReturnCode::OperationViolation; break;
    case 8: CHECK(target.memory().deregister(region)); expected=SemanticReturnCode::BadMemoryKey; break;
    case 9: target.resources().configure_resource(1,3,ResourceSpace::Rma,255); expected=SemanticReturnCode::BadGeneration; break;
    case 10: operation.relative_addressing=false; expected=SemanticReturnCode::PermissionViolation; break;
    case 11: operation.relative_addressing=false; break;
    case 12: operation.relative_addressing=false;
        target.memory().register_storage(2,1,std::make_shared<SparseMemory>(16),7,options);
        expected=SemanticReturnCode::BadMemoryKey; break; // Absolute lookup cannot use Job to choose between equal indices.
    case 13: operation.remote_offset=16; operation.payload.clear(); break; // Empty authorized end-of-region access.
    default: throw std::logic_error("unknown optimized authority scenario");
    }
    // The result buffer belongs to the submitting Job. Wrong-target-Job
    // cases must reach the receiver instead of failing local placement first.
    const auto local=source.memory().register_region(operation.job,1,16,7);
    operation.read_length=static_cast<uint32_t>(operation.payload.size()); operation.payload.clear();
    operation.read_result=ReadResultBuffer{local.key,0,operation.read_length,1,1};
    const uint8_t sentinel=7; region.storage->write(0,&sentinel,1);
    const auto id=source.submit(operation); loop.run_until(5*kMillisecond);
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.operation==id);
    CHECK(completion.status==(expected==SemanticReturnCode::Ok?CompletionStatus::Success:CompletionStatus::RemoteError));
    CHECK(completion.remote_code==static_cast<uint8_t>(expected));
    if (scenario==9) CHECK(completion.remote_generation==255);
    std::vector<uint8_t> bytes(16); region.storage->read(0,bytes.data(),bytes.size());
    std::vector<uint8_t> expected_bytes(16); expected_bytes[0]=7;
    CHECK(bytes==expected_bytes);
    std::vector<uint8_t> expected_result(16); if (scenario==11) expected_result[0]=7;
    CHECK(source.memory().read(operation.job,1,local.key,0,16)==expected_result);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion) && !source.pending() &&
        !source.leased_message_ids() && !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
static void boundaries(pdc_mode mode,bool relative,uint16_t index,uint32_t length) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,8192),target(2,target_host,loop,trace,8192);
    source.memory().add_job(0); target.memory().add_job(0);
    target.resources().map_relative_pid(0,0,0); target.resources().configure_resource(0,index,ResourceSpace::Rma);
    RegionOptions options; options.requested_key=MemoryKeyFormat::Optimized|index; options.idempotent_safe=true;
    const auto region=target.memory().register_storage(0,0,std::make_shared<SparseMemory>(UINT64_MAX),7,options);
    Operation operation; operation.type=OperationType::Read; operation.header_format=RequestHeaderFormat::Small;
    operation.delivery_mode=mode; operation.peer=2; operation.job=0; operation.target_pid=0;
    operation.relative_addressing=relative; operation.remote_key=region.key;
    operation.remote_offset=UINT64_MAX-length; operation.payload.assign(length,0x71);
    const auto local=source.memory().register_region(0,0,8192,7);
    const auto expected=operation.payload;
    region.storage->write(operation.remote_offset,expected.data(),expected.size());
    operation.read_length=length; operation.payload.clear();
    operation.read_result=ReadResultBuffer{local.key,0,length,0,1};
    source.submit(operation); loop.run_until(5*kMillisecond);
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.length==length);
    CHECK(source.memory().read(0,0,local.key,0,length)==expected);
    CHECK(!target.poll_completion(completion) && !source.poll_completion(completion));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
class ReadRevocationPort final : public IPacketPort {
public:
    explicit ReadRevocationPort(IPacketPort& lower):lower_(lower) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (!changed && (packet.SESpkt.bth_type==Optimized_Response_with_Data_Header ||
            packet.SESpkt.bth_type==Semantic_Response_with_Data_Header)) {
            changed=true; revoke();
            if (discard_first) return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver handler) override { lower_.set_receiver(std::move(handler)); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
    std::function<void()> revoke;
    bool changed=false,discard_first=false;
private:
    IPacketPort& lower_;
};
static void result_registration_reuse(RequestHeaderFormat format,pdc_mode mode,uint32_t ack_limit) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); ReadRevocationPort reverse(fabric.add_host(2));
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(ack_limit); target_host.configure_read_ack_data(ack_limit);
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options;
    if (format==RequestHeaderFormat::Small) {
        options.requested_key=MemoryKeyFormat::Optimized|3;
        target.resources().configure_resource(1,3,ResourceSpace::Rma);
    }
    const auto remote=target.memory().register_region(1,1,16,7,options);
    // Use an application key so re-registration is legal; automatic keys may
    // contain provider vendor bits, which applications cannot request.
    RegionOptions original_options; original_options.requested_key=0x2300;
    const auto original=source.memory().register_region(1,1,16,7,original_options);
    remote.storage->write(0,std::vector<uint8_t>(8,0x5b).data(),8);
    original.storage->write(0,std::vector<uint8_t>(8,0xee).data(),8);
    Region replacement{};
    reverse.revoke=[&] {
        CHECK(source.memory().deregister(original)); RegionOptions replacement_options;
        replacement_options.requested_key=original.key;
        replacement=source.memory().register_region(1,1,16,7,replacement_options);
        replacement.storage->write(0,std::vector<uint8_t>(8,0xa5).data(),8);
    };
    Operation operation; operation.type=OperationType::Read; operation.header_format=format;
    operation.delivery_mode=mode; operation.peer=2; operation.remote_key=remote.key; operation.read_length=8;
    operation.read_result=ReadResultBuffer{original.key,0,8,1,1};
    source.submit(operation); loop.run_until(10*kMillisecond);
    Completion completion{};
    CHECK(reverse.changed && source.poll_completion(completion) && completion.status==CompletionStatus::LocalError);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion) && !source.pending());
    std::vector<uint8_t> actual(8); original.storage->read(0,actual.data(),actual.size());
    CHECK(actual==std::vector<uint8_t>(8,0xee));
    CHECK(source.memory().read(1,1,replacement.key,0,8)==std::vector<uint8_t>(8,0xa5));
    CHECK(!target.pending_read_returns() && !target.retained_receive_messages() && !target.retained_read_packets());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
// A resource generation changes admission for a new message. A READ replay
// belongs to the admitted message, just as on the existing STD READ path.
static void replay_keeps_admitted_resource(RequestHeaderFormat format) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); ReadRevocationPort reverse(fabric.add_host(2));
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(128); target_host.configure_read_ack_data(128);
    source_host.configure_retransmission_timeout(100000);
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options; const bool small=format==RequestHeaderFormat::Small;
    if (small) options.requested_key=MemoryKeyFormat::Optimized|3;
    const uint16_t resource=small?3:1;
    target.resources().configure_resource(1,resource,ResourceSpace::Rma,7);
    const auto remote=target.memory().register_region(1,1,16,7,options);
    const auto local=source.memory().register_region(1,1,16,7);
    reverse.discard_first=true;
    reverse.revoke=[&] {
        target.resources().configure_resource(1,resource,ResourceSpace::Rma,8);
        const uint8_t newer=8; remote.storage->write(0,&newer,1);
    };
    Operation operation; operation.type=OperationType::Read; operation.header_format=format;
    operation.peer=2; operation.remote_key=remote.key; operation.target_generation=7; operation.read_length=1;
    operation.read_result=ReadResultBuffer{local.key,0,1,1,1};
    source.submit(operation); loop.run_until(10*kMillisecond); Completion completion{};
    if (!source.poll_completion(completion) || completion.status!=CompletionStatus::Success)
        throw std::runtime_error("admitted READ replay generation failed: format="+std::to_string(unsigned(format))+
            " code="+std::to_string(completion.remote_code));
    CHECK(completion.remote_generation==7 && source.memory().read(1,1,local.key,0,1)==std::vector<uint8_t>{8});
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) {
            for (unsigned scenario=0;scenario<14;++scenario) authority(mode,scenario);
            for (bool relative:{false,true}) for (uint16_t index:{uint16_t{0},uint16_t{4095}}) for (uint32_t length:{0u,1u,8192u})
                boundaries(mode,relative,index,length);
        }
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD})
            for (uint32_t ack_limit:{0u,128u}) result_registration_reuse(format,mode,ack_limit);
        for (auto format:{RequestHeaderFormat::Standard,RequestHeaderFormat::Medium,RequestHeaderFormat::Small})
            replay_keeps_admitted_resource(format);
        std::cout<<"PASS63 optimized READ target MR authority, private origins, zero/index/address/MTU boundaries and source registration identity\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
