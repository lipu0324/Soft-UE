#pragma once
#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

// Fault injection acts on serialized packets only. PDS still owns retries,
// duplicate suppression, congestion accounting, packet IDs and Clear.
class DeferrableFaultPort final : public IPacketPort {
public:
    enum class Action { Pass, Drop, Duplicate, Delay };
    DeferrableFaultPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto action=inject?inject(decoded.packet):Action::Pass;
        if (action==Action::Drop) { ++faults; return SendResult::Accepted; }
        if (action==Action::Delay) {
            ++faults; loop_.after(2*kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        if (action==Action::Duplicate) { ++faults; CHECK(lower_.try_send(frame)==SendResult::Accepted); }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    std::function<Action(const PDStoNET_pkt&)> inject;
    size_t faults=0;
private:
    IPacketPort& lower_; EventLoop& loop_;
};
struct DeferrableFixture {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    DeferrableFaultPort forward{fabric.add_host(1),loop},reverse{fabric.add_host(2),loop};
    PdsHost source_host{1,loop,trace,forward},target_host{2,loop,trace,reverse};
    Endpoint source{1,source_host,loop,trace,16},target{2,target_host,loop,trace,16};
    Region region;
    DeferrableFixture(bool congestion=false,size_t headers=64) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source.memory().add_job(1); target.memory().add_job(1); target.enable_deferrable_capture(headers);
        RegionOptions options; options.requested_key=0x1234;
        region=target.memory().register_region(1,1,256,7,options);
        if (congestion) {
            const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,128);
            source_host.enable_nscc(config); target_host.enable_nscc(config);
        }
    }
    Operation operation(bool tagged,pdc_mode mode,uint64_t context=99) {
        Operation operation; operation.type=tagged?OperationType::DeferrableTaggedSend:OperationType::DeferrableSend;
        operation.peer=2; operation.delivery_mode=mode; operation.tag=UINT64_MAX;
        operation.initiator_id=0; operation.payload.assign(73,0xa5); operation.immediate_data=42; operation.context=context;
        return operation;
    }
    void post(bool tagged,uint64_t context=77,uint32_t capacity=73,uint64_t offset=4) {
        if (tagged) target.post_tagged_receive(1,1,region.key,offset,capacity,{UINT64_MAX,0,uint32_t{0}},context);
        else target.post_receive(1,1,region.key,offset,capacity,context,1,uint32_t{0});
    }
    Completion complete(Endpoint& endpoint,CompletionStatus status,uint64_t context) {
        Completion completion{};
        if (!endpoint.poll_completion(completion)) throw std::runtime_error("missing deferrable completion");
        if (completion.status!=status) std::cerr<<"status="<<unsigned(completion.status)<<" expected="<<unsigned(status)
            <<" code="<<unsigned(completion.remote_code)<<" context="<<completion.context<<'\n';
        CHECK(completion.status==status && completion.context==context);
        return completion;
    }
    void close() {
        Completion completion{}; CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
        if (source.pending() || target.pending() || source.leased_message_ids() || target.leased_message_ids() ||
            source.retained_receive_messages() || target.retained_receive_messages() || target.captured_deferrable_headers())
            std::cerr<<"retained source="<<source.pending()<<'/'<<source.leased_message_ids()<<'/'<<source.retained_receive_messages()
                <<" target="<<target.pending()<<'/'<<target.leased_message_ids()<<'/'<<target.retained_receive_messages()
                <<" headers="<<target.captured_deferrable_headers()<<'\n';
        CHECK(!source.pending() && !target.pending() && !source.leased_message_ids() && !target.leased_message_ids() &&
            !source.retained_receive_messages() && !target.retained_receive_messages() && !target.captured_deferrable_headers());
        source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
    }
};
