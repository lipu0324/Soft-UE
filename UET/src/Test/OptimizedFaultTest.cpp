#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

enum class OptimizedFault { RequestLoss, ResponseLoss, RequestDuplicate, ResponseDuplicate, Reorder, ClearLoss };
class OptimizedFaultPort final : public IPacketPort {
public:
    OptimizedFaultPort(IPacketPort& lower,EventLoop& loop,bool source):lower_(lower),loop_(loop),source_(source) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        if (!enabled) return lower_.try_send(frame);
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (source_ && fault==OptimizedFault::ClearLoss && !clear_lost && packet.PDS_type==RUOD_cp_header &&
            packet.PDS_header.RUOD_cp_header.ctl_type==Clear_cmd) {
            clear_lost=true; return drop(frame);
        }
        const bool request=source_ && packet.PDS_type==RUOD_req_header;
        const bool response=!source_ && packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header;
        if (!request && !response) return lower_.try_send(frame);
        if (response) CHECK(!packet.SESpkt.bth_header.Semantic_Response_Header.message_id);
        if ((request?++requests:++responses)!=1) return lower_.try_send(frame);
        if ((request && fault==OptimizedFault::RequestLoss) || (response && fault==OptimizedFault::ResponseLoss)) return drop(frame);
        if ((request && fault==OptimizedFault::RequestDuplicate) || (response && fault==OptimizedFault::ResponseDuplicate))
            CHECK(lower_.try_send(frame)==SendResult::Accepted);
        if (request && fault==OptimizedFault::Reorder) {
            // Delay after MAC departure, not in the NIC's ROD transmit order.
            // The held original can then arrive after a real RTO replay.
            auto delayed=frame;
            if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
            delayed.transmission_event={};
            loop_.after(200000,[this,delayed] { CHECK(lower_.try_send(delayed)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable writable) override { lower_.set_writable_handler(std::move(writable)); }
    bool enabled=false,clear_lost=false;
    OptimizedFault fault=OptimizedFault::RequestLoss;
    size_t requests=0,responses=0;
private:
    IPacketPort& lower_; EventLoop& loop_; bool source_;
    SendResult drop(const Frame& frame) {
        if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
        return SendResult::Accepted;
    }
};
class ObservedOptimizedStorage final : public MemoryStorage {
public:
    explicit ObservedOptimizedStorage(uint64_t length):backing(length) {}
    uint64_t size() const override { return backing.size(); }
    size_t allocated_pages() const override { return backing.allocated_pages(); }
    void read(uint64_t offset,uint8_t* destination,size_t length) const override { backing.read(offset,destination,length); }
    void write(uint64_t offset,const uint8_t* source,size_t length) override { ++writes; backing.write(offset,source,length); }
    size_t writes=0; SparseMemory backing;
};
static void recovery(RequestHeaderFormat format,OperationType type,pdc_mode mode,bool congestion,OptimizedFault fault) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    OptimizedFaultPort forward(fabric.add_host(1),loop,true),reverse(fabric.add_host(2),loop,false);
    forward.fault=reverse.fault=fault; fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_retransmission_timeout(100000); target_host.configure_retransmission_timeout(100000);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); target.memory().add_job(1);
    auto storage=std::make_shared<ObservedOptimizedStorage>(1024);
    RegionOptions options;
    const bool small=format==RequestHeaderFormat::Small;
    if (small) { options.requested_key=MemoryKeyFormat::Optimized|3; options.idempotent_safe=true;
        target.resources().configure_resource(1,3,ResourceSpace::Rma); }
    const auto region=target.memory().register_storage(1,1,storage,7,options);
    // Establish before delaying a DATA packet, otherwise a delayed SYN merely
    // blocks later DATA locally and would not exercise out-of-order messages.
    CHECK(source_host.open_connection(2,1,mode,false,{1,1,static_cast<uint16_t>(small?3:1)})!=UINT16_MAX);
    loop.run_until(kMillisecond); forward.enabled=reverse.enabled=true;
    const bool send=type==OperationType::Send || type==OperationType::TaggedSend;
    std::set<uint64_t> ids;
    for (uint32_t index=0;index<8;++index) {
        Operation operation; operation.header_format=format; operation.type=type; operation.delivery_mode=mode;
        operation.peer=2; operation.remote_key=region.key; operation.remote_offset=32*index;
        operation.context=index; operation.payload.assign(8,static_cast<uint8_t>(index+1));
        operation.initiator_id=9; operation.tag=1000+index;
        if (send) {
            operation.remote_offset=0; operation.immediate_data=9000+index;
            if (type==OperationType::TaggedSend) target.post_tagged_receive(1,1,region.key,32*index,8,{operation.tag,0,9},100+index);
            else target.post_receive(1,1,region.key,32*index,8,100+index,1,9);
        }
        ids.insert(source.submit(operation));
    }
    loop.run_until(5*kMillisecond);
    Completion completion{}; size_t source_completions=0,target_completions=0;
    while (source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.length==8 && ids.erase(completion.operation)==1);
        ++source_completions;
    }
    while (target.poll_completion(completion)) {
        CHECK(send && completion.status==CompletionStatus::Success && completion.context>=100 && completion.context<108 &&
            completion.immediate_data && *completion.immediate_data>=9000 && *completion.immediate_data<9008);
        const auto sender=*completion.immediate_data-9000;
        CHECK(target.memory().read(1,1,region.key,32*(completion.context-100),8)==std::vector<uint8_t>(8,sender+1));
        if (type==OperationType::TaggedSend) CHECK(completion.tag==1000+sender);
        ++target_completions;
    }
    CHECK(source_completions==8 && ids.empty() && target_completions==(send?8:0) && storage->writes==8);
    if (!send) for (uint32_t index=0;index<8;++index)
        CHECK(target.memory().read(1,1,region.key,32*index,8,small?3:1)==std::vector<uint8_t>(8,index+1));
    // A fresh request carries the current Clear when the idle Clear was lost.
    if (fault==OptimizedFault::ClearLoss) {
        CHECK(forward.clear_lost);
        Operation noop; noop.header_format=format; noop.type=OperationType::Noop; noop.delivery_mode=mode; noop.peer=2;
        noop.target_resource=small?3:1; // Keep the Clear on the same mapped PDC.
        source.submit(noop); loop.run_until(10*kMillisecond);
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    }
    CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        size_t cases=0;
        for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) for (auto fault:{OptimizedFault::RequestLoss,
            OptimizedFault::ResponseLoss,OptimizedFault::RequestDuplicate,OptimizedFault::ResponseDuplicate,
            OptimizedFault::Reorder,OptimizedFault::ClearLoss}) {
            recovery(RequestHeaderFormat::Small,OperationType::Write,mode,congestion,fault); ++cases;
            recovery(RequestHeaderFormat::Small,OperationType::Atomic,mode,congestion,fault); ++cases;
            for (auto type:{OperationType::Write,OperationType::Atomic,OperationType::Send,OperationType::TaggedSend}) {
                recovery(RequestHeaderFormat::Medium,type,mode,congestion,fault); ++cases;
            }
        }
        CHECK(cases==144); std::cout<<"PASS144 no-MID packet faults, same-PDC concurrency, exact WRITE/atomic placement/CQ and Clear recovery\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
