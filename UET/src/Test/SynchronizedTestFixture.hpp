#pragma once
#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class SynchronizedFaultPort final : public IPacketPort {
public:
    enum class Action { Pass, Drop, Duplicate, Delay };
    SynchronizedFaultPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    std::function<Action(const PDStoNET_pkt&)> inject;
    size_t faults=0;
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        const auto action=inject?inject(packet):Action::Pass;
        if (action!=Action::Pass) ++faults;
        if (action==Action::Drop) return SendResult::Accepted;
        if (action==Action::Delay) {
            loop_.after(250000,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        const auto result=lower_.try_send(frame);
        if (action==Action::Duplicate) CHECK(lower_.try_send(frame)==SendResult::Accepted);
        return result;
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; EventLoop& loop_;
};

struct SynchronizedFixture {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    SynchronizedFaultPort forward{fabric.add_host(1),loop},reverse{fabric.add_host(2),loop};
    PdsHost source_host{1,loop,trace,forward},target_host{2,loop,trace,reverse};
    Endpoint source{1,source_host,loop,trace,16},target{2,target_host,loop,trace,16};
    Region destination;
    explicit SynchronizedFixture(bool congestion=false) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source.memory().add_job(1); target.memory().add_job(1);
        destination=target.memory().register_region(1,1,160,7);
        if (congestion) {
            const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,128);
            source_host.enable_nscc(config); target_host.enable_nscc(config);
        }
    }
    Operation write(std::shared_ptr<const SynchronizedGroup> group,pdc_mode mode,uint64_t offset,uint32_t count) {
        Operation operation; operation.type=OperationType::SynchronizedWrite; operation.peer=2; operation.delivery_mode=mode;
        operation.remote_key=destination.key; operation.remote_offset=offset;
        operation.payload.assign(count,0x35); operation.synchronization=std::move(group); return operation;
    }
    Operation completing(std::shared_ptr<const SynchronizedGroup> group,pdc_mode mode,bool atomic) {
        auto operation=write(group,mode,128,atomic?8:3);
        if (atomic) { operation.type=OperationType::SynchronizedAtomic; operation.payload={5,0,0,0,0,0,0,0}; }
        else operation.immediate_data=42;
        return operation;
    }
    void drained() {
        if (target.retained_synchronized_groups() || target.retained_synchronized_members() ||
            target.retained_synchronized_actions() || target.retained_receive_messages())
            std::cerr<<"retained groups="<<target.retained_synchronized_groups()<<" members="<<target.retained_synchronized_members()
                <<" actions="<<target.retained_synchronized_actions()<<" incoming="<<target.retained_receive_messages()<<'\n';
        CHECK(!source.pending() && !source.active_synchronized_source_groups() && !source.leased_message_ids());
        CHECK(!target.retained_synchronized_groups() && !target.retained_synchronized_members() &&
            !target.retained_synchronized_actions() && !target.retained_receive_messages());
    }
    void close() {
        source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
    }
};
