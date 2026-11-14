#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include "../SES/SemanticRequestFields.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void transaction(RequestHeaderFormat format,OperationType type,pdc_mode mode,bool congestion,uint32_t length,bool idempotent) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options;
    if (format==RequestHeaderFormat::Small) {
        options.requested_key=MemoryKeyFormat::Optimized|3; options.idempotent_safe=idempotent;
        target.resources().configure_resource(1,3,ResourceSpace::Rma);
    }
    const auto destination=target.memory().register_storage(1,1,std::make_shared<SparseMemory>(512),7,options);
    Operation operation; operation.header_format=format; operation.type=type; operation.delivery_mode=mode;
    operation.peer=2; operation.remote_key=destination.key; operation.context=99; operation.remote_offset=11;
    operation.payload.resize(length); for (size_t index=0;index<length;++index) operation.payload[index]=index*7+3;
    operation.initiator_id=0x12345678; operation.tag=0xfedcba9876543210ULL;
    const bool send=type==OperationType::Send || type==OperationType::TaggedSend;
    if (send) {
        operation.remote_offset=0; operation.immediate_data=42;
        if (type==OperationType::TaggedSend) target.post_tagged_receive(1,1,destination.key,11,length,
            {operation.tag,0,operation.initiator_id},77);
        else target.post_receive(1,1,destination.key,11,length,77,1,operation.initiator_id);
    }
    size_t requests=0,responses=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto decoded=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto& packet=decoded.packet;
        if (packet.PDS_type==RUOD_req_header && frame.source==1) {
            CHECK(packet.SESpkt.bth_type==(format==RequestHeaderFormat::Small?Optimized_Header:Small_Message_RMA_Header));
            const auto fields=semantic_request_fields(packet.SESpkt);
            CHECK(fields && !fields->has_message_id && !fields->header.msg_id && fields->header.som && fields->header.eom);
            ++requests;
        }
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header) {
            CHECK(!packet.SESpkt.bth_header.Semantic_Response_Header.message_id); ++responses;
        }
    });
    const auto id=source.submit(operation); loop.run_until(5*kMillisecond);
    Completion completion{};
    if (!source.poll_completion(completion) || completion.status!=CompletionStatus::Success)
        throw std::runtime_error("optimized transaction failed: format="+std::to_string(unsigned(format))+" type="+
            std::to_string(unsigned(type))+" mode="+std::to_string(mode)+" status="+std::to_string(unsigned(completion.status))+
            " code="+std::to_string(completion.remote_code)+" length="+std::to_string(length)+" idempotent="+std::to_string(idempotent));
    CHECK(completion.operation==id && completion.context==99 && completion.length==length && !source.poll_completion(completion));
    if (send) {
        CHECK(target.poll_completion(completion) && completion.receive && completion.context==77 &&
            completion.status==CompletionStatus::Success && completion.immediate_data==42 && completion.length==length);
        CHECK(completion.tag==(type==OperationType::TaggedSend?std::optional<uint64_t>{operation.tag}:std::nullopt));
    }
    CHECK(!target.poll_completion(completion));
    if (type!=OperationType::Noop) CHECK(target.memory().read(1,1,destination.key,11,length,
        format==RequestHeaderFormat::Small?std::optional<uint16_t>{3}:std::optional<uint16_t>{1})==operation.payload);
    CHECK(requests==1 && responses>=1 && !source.pending() && !source.leased_message_ids() && !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        size_t cases=0;
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) {
            for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) {
                transaction(format,OperationType::Noop,mode,congestion,0,false); ++cases;
                for (uint32_t length:{0u,1u,73u,128u}) {
                    transaction(format,OperationType::Write,mode,congestion,length,false); ++cases;
                    if (format==RequestHeaderFormat::Small) { transaction(format,OperationType::Write,mode,congestion,length,true); ++cases; }
                }
            }
            for (auto type:{OperationType::Send,OperationType::TaggedSend}) for (uint32_t length:{0u,1u,73u,128u}) {
                transaction(RequestHeaderFormat::Medium,type,mode,congestion,length,false); ++cases;
            }
        }
        CHECK(cases==88); std::cout<<"PASS88 optimized no-MID native WRITE/NOOP/SEND/tagged, key metadata, completion and Clear\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
