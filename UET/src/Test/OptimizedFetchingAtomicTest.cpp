#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/SemanticRequestFields.hpp"
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
        const auto fields=semantic_request_fields(packet.SESpkt);
        if (packet.PDS_type==RUOD_req_header && fields && fields->header.opcode==4) {
            ++request_attempts;
            CHECK(packet.SESpkt.eth_type==Atomic_Operation_Extension_Header);
            CHECK(!fields->has_message_id && fields->header.som && fields->header.eom);
        }
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Optimized_Response_with_Data_Header) {
            ++data_attempts;
            CHECK(packet.PDS_header.RUOD_ack_header.flags.req&1); // Required delivery survives every replay.
            CHECK(packet.SESpkt.bth_header.Optimized_Response_with_Data_Header.payload_length<=16);
            if (corrupt_result && !corrupted) {
                corrupted=true; auto altered=packet;
                auto& result=altered.SESpkt.bth_header.Optimized_Response_with_Data_Header;
                if (corrupt_result==1) ++result.original_request_psn;
                else if (corrupt_result==2) ++result.job_id;
                else if (corrupt_result==3) {
                    const auto original_id=0; // No MID exists in the original optimized request.
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

void scalar_operation(RequestHeaderFormat format,pdc_mode mode,bool congestion,uint32_t ack_limit,IntegerAtomicDatatype datatype,
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
    RegionOptions remote_options;
    if (format==RequestHeaderFormat::Small) {
        remote_options.requested_key=MemoryKeyFormat::Optimized|3;
        remote_options.idempotent_safe=congestion; // Both implicit key metadata variants, without weakening atomic deduplication.
        target.resources().configure_resource(1,3,ResourceSpace::Rma,7);
    }
    const auto remote=target.memory().register_region(1,1,64,7,remote_options);
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
    operation.target_generation=7; operation.header_format=format;
    operation.remote_key=remote.key; operation.remote_offset=16; operation.atomic_operation=atomic_operation;
    operation.atomic_datatype=datatype; operation.payload=scalar_bytes(2,width);
    if (dual_operand_atomic(atomic_operation)) operation.atomic_compare=scalar_bytes(3,width);
    operation.atomic_result=AtomicResultBuffer{local.key,7,static_cast<uint32_t>(width),1,1};
    const auto submitted=source.submit(operation);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2; noop.delivery_mode=mode;
    noop.target_generation=7; noop.target_resource=format==RequestHeaderFormat::Small?3:1;
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

// Zero-byte get/put still authenticates an atomic MR, but changes no byte.
static void zero_operation(RequestHeaderFormat format,pdc_mode mode,IntegerAtomicOperation atomic_operation) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options;
    if (format==RequestHeaderFormat::Small) {
        options.requested_key=MemoryKeyFormat::Optimized|3;
        target.resources().configure_resource(1,3,ResourceSpace::Rma);
    }
    const auto region=target.memory().register_region(1,1,8,7,options);
    const uint8_t sentinel=0x7b; region.storage->write(0,&sentinel,1);
    Operation operation; operation.type=OperationType::FetchingAtomic; operation.header_format=format;
    operation.delivery_mode=mode; operation.peer=2; operation.remote_key=region.key;
    operation.atomic_operation=atomic_operation; operation.zero_length_atomic=true;
    source.submit(operation); loop.run_until(5*kMillisecond);
    Completion completion{}; uint8_t actual=0; region.storage->read(0,&actual,1);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && !completion.length);
    CHECK(actual==sentinel && !source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK(!source.leased_message_ids() && !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
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
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium})
            for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true}) {
            for (unsigned datatype=0;datatype<10;++datatype) for (const auto [operation,updated]:cases)
                scalar_operation(format,mode,congestion,0,static_cast<IntegerAtomicDatatype>(datatype),operation,updated);
            for (unsigned fault=1;fault<=7;++fault)
                scalar_operation(format,mode,congestion,8192,IntegerAtomicDatatype::Uint128,IntegerAtomicOperation::Sum,5,fault);
        }
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium})
            for (auto mode:{RUD,ROD}) for (auto operation:{IntegerAtomicOperation::Read,IntegerAtomicOperation::Write})
                zero_operation(format,mode,operation);
        std::cout<<"PASS1664 optimized fetching/CAS, DATA_SMALL PSN binding, cached old results, loss/duplicates, MR revocation, zero operations and NSCC\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
