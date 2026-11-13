#pragma once
#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class RendezvousFaultPort final : public IPacketPort {
public:
    enum class Action { Pass, Drop, Duplicate, Delay };
    RendezvousFaultPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        const auto action=inject?inject(packet):Action::Pass;
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
struct RendezvousFixture {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    RendezvousFaultPort forward{fabric.add_host(1),loop},reverse{fabric.add_host(2),loop};
    PdsHost source_host{1,loop,trace,forward},target_host{2,loop,trace,reverse};
    Endpoint source{1,source_host,loop,trace,16},target{2,target_host,loop,trace,16};
    std::shared_ptr<SparseMemory> source_storage=std::make_shared<SparseMemory>(256);
    std::shared_ptr<SparseMemory> target_storage=std::make_shared<SparseMemory>(256);
    Region source_region,target_region;
    std::vector<uint8_t> bytes;
    RendezvousFixture(bool standalone=false,bool congestion=false) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source_host.configure_read_ack_data(standalone?0:16); target_host.configure_read_ack_data(standalone?0:16);
        source.memory().add_job(1); target.memory().add_job(1);
        RegionOptions options; options.requested_key=0x1234;
        source_region=source.memory().register_storage(1,1,source_storage,1,options);
        options.requested_key=0x2222; target_region=target.memory().register_storage(1,1,target_storage,7,options);
        bytes.resize(73); for (uint32_t byte=0;byte<73;++byte) bytes[byte]=static_cast<uint8_t>(byte*7+3);
        source_storage->write(4,bytes.data(),bytes.size());
        if (congestion) {
            const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,148);
            source_host.enable_nscc(config); target_host.enable_nscc(config);
        }
    }
    Operation operation(bool tagged,pdc_mode mode,uint64_t context=99,uint64_t source_offset=4,uint32_t eager=73) {
        Operation operation; operation.type=tagged?OperationType::RendezvousTaggedSend:OperationType::RendezvousSend;
        operation.delivery_mode=mode; operation.peer=2; operation.initiator_id=0; operation.tag=UINT64_MAX;
        operation.context=context; operation.immediate_data=42;
        operation.rendezvous_source=RendezvousBuffer{source_region.key,source_offset,73,1,1,0};
        operation.rendezvous_eager_length=eager; return operation;
    }
    void post(bool tagged,uint64_t context=77,uint64_t offset=4,uint32_t capacity=73) {
        if (tagged) target.post_tagged_receive(1,1,target_region.key,offset,capacity,{UINT64_MAX,0,uint32_t{0}},context);
        else target.post_receive(1,1,target_region.key,offset,capacity,context,1,uint32_t{0});
    }
    Completion take(Endpoint& endpoint,uint64_t context) {
        Completion completion{}; CHECK(endpoint.poll_completion(completion) && completion.context==context); return completion;
    }
    Completion complete(Endpoint& endpoint,uint64_t context,CompletionStatus status) {
        const auto completion=take(endpoint,context);
        if (completion.status!=status) std::cerr<<"context="<<context<<" status="<<unsigned(completion.status)
            <<" expected="<<unsigned(status)<<" code="<<unsigned(completion.remote_code)<<'\n';
        CHECK(completion.status==status); return completion;
    }
    void close() {
        Completion completion{}; CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
        if (source.pending() || target.pending() || source.leased_message_ids() || target.leased_message_ids() ||
            source.retained_receive_messages() || target.retained_receive_messages() || target.retained_rendezvous_receives())
            std::cerr<<"retained source="<<source.pending()<<'/'<<source.leased_message_ids()<<'/'<<source.retained_receive_messages()
                <<" target="<<target.pending()<<'/'<<target.leased_message_ids()<<'/'<<target.retained_receive_messages()
                <<" rendezvous="<<target.retained_rendezvous_receives()<<'\n';
        CHECK(!source.pending() && !target.pending() && !source.leased_message_ids() && !target.leased_message_ids() &&
            !source.retained_receive_messages() && !target.retained_receive_messages() && !target.retained_rendezvous_receives() &&
            !source.retained_read_packets() && !target.retained_read_packets() && !source.pending_read_returns() && !target.pending_read_returns());
        source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
    }
};
