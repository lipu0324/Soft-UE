#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

std::vector<uint8_t> scalar_bytes(uint64_t value,size_t width) {
    std::vector<uint8_t> bytes(width,0);
    for (size_t byte=0;byte<std::min<size_t>(8,width);++byte) bytes[byte]=static_cast<uint8_t>(value>>(8*byte));
    return bytes;
}

class FetchResultPort final : public IPacketPort {
public:
    explicit FetchResultPort(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto& packet=decoded.packet;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            packet.SESpkt.bth_header.Standard_Header.opcode==4) {
            ++request_attempts;
            CHECK(packet.SESpkt.eth_type==Atomic_Operation_Extension_Header);
            CHECK(packet.SESpkt.bth_header.Standard_Header.som && packet.SESpkt.bth_header.Standard_Header.eom);
        }
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header) {
            ++data_attempts;
            CHECK(packet.PDS_header.RUOD_ack_header.flags.req&1); // Required delivery survives every replay.
            CHECK(packet.SESpkt.bth_header.Semantic_Response_with_Data_Header.payload_length<=16);
            if (corrupt_result && !corrupted) {
                corrupted=true; auto altered=packet;
                auto& result=altered.SESpkt.bth_header.Semantic_Response_with_Data_Header;
                if (corrupt_result==1) ++result.message_offset;
                else if (corrupt_result==2) ++result.payload_length;
                else if (corrupt_result==3) {
                    const auto original_id=result.read_request_msg_id;
                    const auto job=result.job_id;
                    altered.PDS_header.RUOD_ack_header.next_hdr=UET_HDR_RESPONSE;
                    altered.SESpkt={}; altered.SESpkt.bth_type=Semantic_Response_Header;
                    auto& empty=altered.SESpkt.bth_header.Semantic_Response_Header;
                    empty.opcode=0; empty.return_code=1; empty.message_id=original_id; empty.job_id=job;
                } else throw std::logic_error("unknown fetching result corruption");
                auto changed=frame; changed.bytes=UetWireCodec::encode(altered,decoded.network);
                return lower_.try_send(changed);
            }
            if (!dropped && lose_result) {
                dropped=true; if (after_loss) after_loss(); return SendResult::Accepted;
            }
        }
        const auto status=lower_.try_send(frame);
        if (duplicate && status==SendResult::Accepted) CHECK(lower_.try_send(frame)==SendResult::Accepted);
        return status;
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool lose_result=false,dropped=false,duplicate=false;
    unsigned corrupt_result=0;
    bool corrupted=false;
    size_t data_attempts=0,request_attempts=0;
    std::function<void()> after_loss;
private:
    IPacketPort& lower_;
};

void scalar_operation(pdc_mode mode,bool congestion,uint32_t ack_limit,IntegerAtomicDatatype datatype,
                      IntegerAtomicOperation atomic_operation,uint64_t updated_value,unsigned fault=0) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    FetchResultPort forward(fabric.add_host(1)),reverse(fabric.add_host(2));
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(ack_limit); target_host.configure_read_ack_data(ack_limit);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1132);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    target.resources().configure_resource(1,1,ResourceSpace::Rma,7);
    const auto width=integer_atomic_width(datatype);
    RegionOptions local_options; local_options.requested_key=0x1234;
    const auto local=source.memory().register_region(1,1,64,Access::Read|Access::Write,local_options);
    std::optional<Region> replacement;
    const auto remote=target.memory().register_region(1,1,64,7);
    const auto old_value=scalar_bytes(3,width);
    target.memory().write(1,1,remote.key,16,old_value);
    source.memory().write(1,1,local.key,7,std::vector<uint8_t>(width,0xee));
    reverse.lose_result=fault>=1 && fault<=4; forward.duplicate=reverse.duplicate=fault==1;
    if (fault>=5) reverse.corrupt_result=fault-4;
    reverse.after_loss=[&] {
        if (fault==2) target.memory().write(1,1,remote.key,16,scalar_bytes(99,width));
        if (fault==3) target.memory().deregister(remote);
        if (fault==4) {
            source.memory().deregister(local);
            replacement=source.memory().register_region(1,1,64,Access::Read|Access::Write,local_options);
            source.memory().write(1,1,replacement->key,7,std::vector<uint8_t>(width,0xa5));
        }
    };
    Operation operation; operation.type=OperationType::FetchingAtomic; operation.peer=2; operation.delivery_mode=mode;
    operation.target_generation=7;
    operation.remote_key=remote.key; operation.remote_offset=16; operation.atomic_operation=atomic_operation;
    operation.atomic_datatype=datatype; operation.payload=scalar_bytes(2,width);
    if (dual_operand_atomic(atomic_operation)) operation.atomic_compare=scalar_bytes(3,width);
    operation.atomic_result=AtomicResultBuffer{local.key,7,static_cast<uint32_t>(width),1,1};
    const auto submitted=source.submit(operation);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2; noop.delivery_mode=mode;
    noop.target_generation=7;
    const auto following=source.submit(noop); loop.run(100000);
    Completion completion{}; size_t atomics=0,noops=0;
    while (source.poll_completion(completion)) {
        if (completion.operation==submitted) {
            ++atomics;
            CHECK(completion.status==(fault==4?CompletionStatus::LocalError:CompletionStatus::Success));
            CHECK(completion.length==(fault==4?0:width));
            if (fault!=4) CHECK(completion.remote_generation==7);
        } else { CHECK(completion.operation==following && completion.status==CompletionStatus::Success); ++noops; }
    }
    CHECK(atomics==1 && noops==1 && !target.poll_completion(completion));
    std::vector<uint8_t> actual(width); local.storage->read(7,actual.data(),width);
    CHECK(actual==(fault==4?std::vector<uint8_t>(width,0xee):old_value));
    if (replacement) CHECK(source.memory().read(1,1,replacement->key,7,width)==std::vector<uint8_t>(width,0xa5));
    remote.storage->read(16,actual.data(),width);
    CHECK(actual==scalar_bytes(fault==2?99:updated_value,width));
    size_t executions=0;
    for (const auto& event:trace.events()) if (event.event=="fetching_atomic_executed") ++executions;
    CHECK(executions==1 && reverse.dropped==(fault>=1 && fault<=4) && reverse.corrupted==(fault>=5) &&
        reverse.data_attempts>=(fault?2:1));
    CHECK(source.leased_message_ids()==0 && target.retained_receive_messages()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

void local_validation() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42); auto& network=fabric.add_host(1);
    PdsHost host(1,loop,trace,network); Endpoint source(1,host,loop,trace); source.memory().add_job(1);
    const auto local=source.memory().register_region(1,1,32,Access::Read|Access::Write);
    Operation operation; operation.type=OperationType::FetchingAtomic; operation.peer=2;
    operation.atomic_result=AtomicResultBuffer{local.key,0,8,1,1}; operation.payload=scalar_bytes(1,8);
    const auto reject=[&](Operation request,CompletionStatus expected) {
        const auto submitted=source.submit(std::move(request)); Completion completion{};
        CHECK(source.poll_completion(completion) && completion.operation==submitted && completion.status==expected);
        CHECK(source.queued_fragments()==0 && trace.events().empty());
    };
    auto invalid=operation; invalid.payload.resize(7); reject(invalid,CompletionStatus::InvalidRequest);
    invalid=operation; invalid.atomic_result.reset(); reject(invalid,CompletionStatus::InvalidRequest);
    invalid=operation; invalid.atomic_datatype=static_cast<IntegerAtomicDatatype>(10); reject(invalid,CompletionStatus::Unsupported);
    invalid=operation; invalid.atomic_operation=IntegerAtomicOperation::CompareSwapEqual; reject(invalid,CompletionStatus::InvalidRequest);
    invalid=operation; invalid.remote_offset=1; reject(invalid,CompletionStatus::InvalidRequest);
    invalid=operation; invalid.atomic_result->capacity=7; reject(invalid,CompletionStatus::InvalidRequest);
    invalid=operation; invalid.immediate_data=1; reject(invalid,CompletionStatus::InvalidRequest);
    invalid=operation; invalid.atomic_result->key=0; reject(invalid,CompletionStatus::LocalError);
    CHECK(source.capabilities().fetching_atomic && source.capabilities().fetching_atomic_datatypes.size()==10 && !source.capabilities().hpc);
    source.close(); host.close(); CHECK(loop.pending()==0);
}

void remote_errors_and_read_generation() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); source.memory().add_job(2); target.memory().add_job(1);
    const auto local=source.memory().register_region(1,1,64,Access::Read|Access::Write);
    const auto other_job_local=source.memory().register_region(2,1,64,Access::Read|Access::Write);
    const auto remote=target.memory().register_region(1,1,64,7);
    const auto no_atomic=target.memory().register_region(1,1,64,Access::Read|Access::Write);
    Operation operation; operation.type=OperationType::FetchingAtomic; operation.peer=2;
    operation.remote_key=remote.key; operation.payload=scalar_bytes(1,8);
    operation.atomic_result=AtomicResultBuffer{local.key,0,8,1,1};
    const auto reject=[&](Operation invalid,uint8_t code) {
        const auto submitted=source.submit(std::move(invalid)); loop.run(100000); Completion completion{};
        CHECK(source.poll_completion(completion) && completion.operation==submitted &&
            completion.status==CompletionStatus::RemoteError && completion.remote_code==code && !completion.length);
        CHECK(source.leased_message_ids()==0 && target.retained_receive_messages()==0);
        CHECK(target.memory().read(1,1,remote.key,0,64)==std::vector<uint8_t>(64,0));
        CHECK(source.memory().read(1,1,local.key,0,64)==std::vector<uint8_t>(64,0));
    };
    auto invalid=operation; invalid.remote_key=0; reject(invalid,0x1c);
    invalid=operation; invalid.remote_key=no_atomic.key; reject(invalid,0x18);
    invalid=operation; invalid.remote_offset=64; reject(invalid,0x1d);
    invalid=operation; invalid.job=2; invalid.atomic_result->key=other_job_local.key; reject(invalid,0x1b);
    invalid=operation; invalid.target_pid=2; reject(invalid,0x1a);
    invalid=operation; invalid.target_resource=2; reject(invalid,0x19);
    const auto revoked=target.memory().register_region(1,1,64,7); target.memory().deregister(revoked);
    invalid=operation; invalid.remote_key=revoked.key; reject(invalid,0x1c);

    // Data ACK carries no resource generation. A successful READ must report
    // its nonzero admitted generation so a provider does not reset its peer
    // generation immediately after a BAD_GENERATION semantic retry.
    target.resources().configure_resource(1,1,ResourceSpace::Rma,7);
    Operation read; read.type=OperationType::Read; read.peer=2; read.remote_key=remote.key;
    read.read_length=8; read.target_generation=7; read.read_result=ReadResultBuffer{local.key,0,8,1,1};
    const auto submitted=source.submit(read); loop.run(100000); Completion completion{};
    CHECK(source.poll_completion(completion) && completion.operation==submitted &&
        completion.status==CompletionStatus::Success && completion.remote_generation==7);
    for (const auto datatype:{IntegerAtomicDatatype::Uint64,IntegerAtomicDatatype::Uint128}) {
        const auto width=integer_atomic_width(datatype);
        const auto exact_region=target.memory().register_region(1,1,width,7);
        Operation compare; compare.type=OperationType::FetchingAtomic; compare.peer=2;
        compare.target_generation=7; compare.remote_key=exact_region.key; compare.atomic_datatype=datatype;
        compare.atomic_operation=IntegerAtomicOperation::CompareSwapEqual;
        compare.payload=scalar_bytes(4,width); compare.atomic_compare=scalar_bytes(0,width);
        compare.atomic_result=AtomicResultBuffer{local.key,16,static_cast<uint32_t>(width),1,1};
        const auto comparison=source.submit(compare); loop.run(100000);
        CHECK(source.poll_completion(completion) && completion.operation==comparison &&
            completion.status==CompletionStatus::Success && completion.length==width);
        // The32B request describes one8/16B target element, not a32B MR access.
        CHECK(target.memory().read(1,1,exact_region.key,0,width)==scalar_bytes(4,width));
    }
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        const std::vector<std::pair<IntegerAtomicOperation,uint64_t>> cases{
            {IntegerAtomicOperation::Minimum,2},{IntegerAtomicOperation::Maximum,3},{IntegerAtomicOperation::Sum,5},
            {IntegerAtomicOperation::Difference,1},{IntegerAtomicOperation::Product,6},{IntegerAtomicOperation::LogicalOr,1},
            {IntegerAtomicOperation::LogicalAnd,1},{IntegerAtomicOperation::BitwiseOr,3},{IntegerAtomicOperation::BitwiseAnd,2},
            {IntegerAtomicOperation::LogicalXor,0},{IntegerAtomicOperation::BitwiseXor,1},{IntegerAtomicOperation::Read,3},
            {IntegerAtomicOperation::Write,2},{IntegerAtomicOperation::CompareSwapEqual,2},{IntegerAtomicOperation::CompareSwapNotEqual,3},
            {IntegerAtomicOperation::CompareSwapLessEqual,2},{IntegerAtomicOperation::CompareSwapLess,3},
            {IntegerAtomicOperation::CompareSwapGreaterEqual,2},{IntegerAtomicOperation::CompareSwapGreater,3},
            {IntegerAtomicOperation::MaskedSwap,1}};
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true}) {
            for (unsigned datatype=0;datatype<10;++datatype) for (const auto [operation,updated]:cases)
                scalar_operation(mode,congestion,0,static_cast<IntegerAtomicDatatype>(datatype),operation,updated);
            for (unsigned fault=1;fault<=7;++fault)
                scalar_operation(mode,congestion,8192,IntegerAtomicDatatype::Uint128,IntegerAtomicOperation::Sum,5,fault);
        }
        local_validation(); remote_errors_and_read_generation();
        std::cout<<"PASS native fetching/CAS, one-element and padded fields, cached old results, loss/duplicates, MR revocation and NSCC\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
