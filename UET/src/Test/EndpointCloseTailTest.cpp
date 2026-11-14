#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void partial_close(OperationType type,pdc_mode mode,bool congestion,uint32_t ack_limit=0) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    LinkConfig link; link.delay_ns=100000;
    fabric.add_link(1,2,link); fabric.add_link(2,1,link);
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.services().psn_ranges.local_packet_capacity=1;
    source_host.configure_read_ack_data(ack_limit); target_host.configure_read_ack_data(ack_limit);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint previous(1,source_host,loop,trace,128,100*kMillisecond,nullptr,1);
    Endpoint target(2,target_host,loop,trace,128,100*kMillisecond,nullptr,8,1);
    previous.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,4096,7);
    const bool read=type==OperationType::Read;
    const bool send=type==OperationType::Send || type==OperationType::TaggedSend;
    std::optional<Region> result;
    size_t reads=0,tails=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (frame.source==1 && packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            packet.SESpkt.bth_header.Standard_Header.opcode==0x0f) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            CHECK(header.eom && !header.som && packet.SESpkt.payload.empty()); ++tails;
        }
    });
    Operation operation; operation.type=type; operation.delivery_mode=mode;
    operation.peer=2; operation.remote_key=region.key; operation.tag=77;
    operation.atomic_datatype=IntegerAtomicDatatype::Uint8;
    if (read) {
        result=previous.memory().register_region(1,1,4096,7);
        operation.read_length=4096; operation.read_result=ReadResultBuffer{result->key,0,4096,1,1};
        region.storage->write(0,std::vector<uint8_t>(4096,0x77).data(),4096);
    } else {
        operation.payload_source=std::make_shared<GeneratedPayload>(4096,[&](uint64_t,uint8_t* bytes,size_t count) {
            ++reads; std::memset(bytes,0x66,count);
        });
    }
    if (type==OperationType::Send) target.post_receive(1,1,region.key,0,4096,42);
    if (type==OperationType::TaggedSend) target.post_tagged_receive(1,1,region.key,0,4096,{77,0,1},42);
    previous.submit(operation); loop.run_until(1);
    CHECK(previous.pending() && (read || (reads && reads*128<4096)));
    const auto reads_before_close=reads;
    previous.close(); Completion completion{};
    CHECK(previous.poll_completion(completion) && completion.status==CompletionStatus::Cancelled);
    // A replacement is present before reverse READ data arrives. It must
    // drain old results without placing them in the closed object's MR.
    Endpoint replacement(1,source_host,loop,trace,128); replacement.memory().add_job(1);
    Operation next; next.type=OperationType::Noop; next.delivery_mode=mode; next.peer=2;
    const auto next_id=replacement.submit(next); loop.run_until(90*kMillisecond);
    if (target.retained_receive_messages() || source_host.services().retired_semantic_messages.size())
        throw std::runtime_error("partial close leaked message: type="+std::to_string(unsigned(type))+" mode="+
            std::to_string(mode)+" nscc="+std::to_string(congestion)+" ack="+std::to_string(ack_limit));
    CHECK(reads==reads_before_close && tails==1);
    CHECK(replacement.poll_completion(completion) && completion.operation==next_id && completion.status==CompletionStatus::Success);
    CHECK(!replacement.poll_completion(completion));
    if (send) {
        CHECK(target.poll_completion(completion) && completion.receive && completion.context==42 &&
            completion.status==CompletionStatus::RemoteError && completion.remote_code==static_cast<uint8_t>(SemanticReturnCode::InitiatorError) &&
            completion.length==reads_before_close*128);
    }
    CHECK(!target.poll_completion(completion));
    if (read) {
        CHECK(previous.memory().read(1,1,result->key,0,4096)==std::vector<uint8_t>(4096));
        CHECK(!target.pending_read_returns() && !target.retained_read_packets());
    } else {
        std::vector<uint8_t> expected(4096); std::fill_n(expected.begin(),reads_before_close*128,0x66);
        CHECK(target.memory().read(1,1,region.key,0,4096)==expected);
    }
    replacement.close(); target.close(); source_host.close(); target_host.close();
    CHECK(!loop.pending() && !source_host.services().retired_semantic_messages.size());
}
static void never_started_message_has_no_transport_lease(bool shutdown_first) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.services().psn_ranges.local_packet_capacity=1;
    Endpoint previous(1,source_host,loop,trace,128,100*kMillisecond,nullptr,1),target(2,target_host,loop,trace,128);
    previous.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,4096,7);
    Operation first; first.type=OperationType::Write; first.delivery_mode=RUD; first.peer=2;
    first.remote_key=region.key; first.payload.assign(4096,0x33); previous.submit(first);
    Operation queued; queued.type=OperationType::Noop; queued.delivery_mode=RUD; queued.peer=2; previous.submit(queued);
    if (shutdown_first) source_host.close();
    previous.close(); Completion completion{}; size_t cancellations=0;
    while (previous.poll_completion(completion)) { CHECK(completion.status==CompletionStatus::Cancelled); ++cancellations; }
    CHECK(cancellations==2 && source_host.services().retired_semantic_messages.size()==size_t(!shutdown_first));
    if (!shutdown_first) {
        source_host.services().semantic_message_cursor=1; // ID2 never entered PDS and is safe to reuse now.
        Endpoint replacement(1,source_host,loop,trace,128); replacement.memory().add_job(1);
        replacement.submit(queued); loop.run_until(10*kMillisecond);
        CHECK(replacement.poll_completion(completion) && completion.status==CompletionStatus::Success);
        CHECK(!source_host.services().retired_semantic_messages.size()); replacement.close();
    }
    target.close(); source_host.close(); target_host.close(); loop.run_until(20*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) {
            for (auto type:{OperationType::Write,OperationType::Send,OperationType::TaggedSend,OperationType::Atomic})
                partial_close(type,mode,congestion);
            for (uint32_t ack_limit:{0u,128u}) partial_close(OperationType::Read,mode,congestion,ack_limit);
        }
        never_started_message_has_no_transport_lease(false); never_started_message_has_no_transport_lease(true);
        std::cout<<"PASS26 partial Endpoint close tails, reader lifetime, both READ channels, NSCC and unsent lease boundaries\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
