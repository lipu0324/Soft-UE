#include "Check.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class ControlledRudiPort final : public IPacketPort {
public:
    ControlledRudiPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        if (blocked) return SendResult::WouldBlock;
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (observe) observe(packet);
        ++transmissions;
        if (discard) {
            if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override {
        writable_=callback; lower_.set_writable_handler(std::move(callback));
    }
    void release() { blocked=false; if (writable_) writable_(); }
    bool blocked=false,discard=false;
    size_t transmissions=0;
    std::function<void(const PDStoNET_pkt&)> observe;
private:
    IPacketPort& lower_; EventLoop& loop_; Writable writable_;
};
struct RudiPair {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    ControlledRudiPort forward{fabric.add_host(1),loop},reverse{fabric.add_host(2),loop};
    PdsHost source_host{1,loop,trace,forward},target_host{2,loop,trace,reverse};
    Endpoint source{1,source_host,loop,trace,64,100000},target{2,target_host,loop,trace,64};
    Region remote{},result{};
    RudiPair() {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source_host.configure_retransmission_timeout(10000); source_host.configure_retry_limit(1);
        source.memory().add_job(1); target.memory().add_job(1);
        remote=target.memory().register_region(1,1,512,7,true);
        RegionOptions options; options.requested_key=0x2200;
        result=source.memory().register_storage(1,1,std::make_shared<SparseMemory>(512),7,options);
    }
    Operation write() const {
        Operation operation; operation.type=OperationType::Write; operation.delivery_mode=RUDI;
        operation.peer=2; operation.remote_key=remote.key; operation.payload=std::vector<uint8_t>(257,0x5a); return operation;
    }
    size_t close() { source.close(); target.close(); source_host.close(); target_host.close(); return loop.pending(); }
};
static void retry_exhaustion_repeats_only_idempotent_writes() {
    RudiPair pair; pair.reverse.discard=true;
    auto operation=pair.write(); operation.payload={7};
    const auto id=pair.source.submit(operation); pair.loop.run_until(80000);
    Completion completion{}; CHECK(pair.source.poll_completion(completion));
    CHECK(completion.operation==id && completion.status==CompletionStatus::Timeout && !pair.source.poll_completion(completion));
    CHECK(pair.forward.transmissions==2 && pair.reverse.transmissions==2);
    CHECK(pair.target.memory().read(1,1,pair.remote.key,0,1)==std::vector<uint8_t>{7});
    CHECK(!pair.target.poll_completion(completion) && !pair.source.leased_message_ids()); CHECK(!pair.close());
}
static void cancel_backpressured_source(bool deadline) {
    RudiPair pair; pair.forward.blocked=true;
    const auto id=pair.source.submit(pair.write()); pair.loop.run_until(deadline?100001:50000);
    if (!deadline) CHECK(pair.source.cancel_rudi(id));
    Completion completion{}; CHECK(pair.source.poll_completion(completion));
    CHECK(completion.operation==id && completion.status==(deadline?CompletionStatus::Timeout:CompletionStatus::Cancelled));
    CHECK(!pair.source.poll_completion(completion) && !pair.forward.transmissions && !pair.source.queued_fragments());
    pair.forward.release(); pair.loop.run_until(150000);
    CHECK(!pair.forward.transmissions && pair.target.memory().read(1,1,pair.remote.key,0,257)==std::vector<uint8_t>(257));
    // Cancellation/deadline must leave no phantom PDC lease or dead producer.
    auto next=pair.write(); next.payload={8}; pair.source.submit(next); pair.loop.run_until(200000);
    CHECK(pair.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(pair.target.memory().read(1,1,pair.remote.key,0,1)==std::vector<uint8_t>{8}); CHECK(!pair.close());
}
static void returned_data_never_rebinds_a_reused_key() {
    RudiPair pair; bool replaced=false; Region replacement{};
    pair.target.memory().write(1,1,pair.remote.key,0,std::vector<uint8_t>(257,0x7b));
    pair.reverse.observe=[&](const PDStoNET_pkt& packet) {
        if (replaced || packet.SESpkt.bth_type!=Semantic_Response_with_Data_Header) return;
        replaced=true; CHECK(pair.source.memory().deregister(pair.result));
        RegionOptions options; options.requested_key=pair.result.key;
        replacement=pair.source.memory().register_storage(1,1,std::make_shared<SparseMemory>(512),7,options);
    };
    auto operation=pair.write(); operation.type=OperationType::Read; operation.payload.clear();
    operation.read_length=257; operation.read_result=ReadResultBuffer{pair.result.key,0,257};
    pair.source.submit(operation); pair.loop.run_until(80000);
    Completion completion{}; CHECK(pair.source.poll_completion(completion) && completion.status==CompletionStatus::LocalError);
    CHECK(replaced && pair.source.memory().read(1,1,replacement.key,0,257)==std::vector<uint8_t>(257));
    CHECK(!pair.source.poll_completion(completion) && !pair.source.leased_message_ids()); CHECK(!pair.close());
}
static void endpoint_replacement_preserves_packet_identity() {
    RudiPair pair; pair.forward.blocked=true;
    pair.source.submit(pair.write()); pair.loop.run_until(1000);
    const auto next_packet=pair.source_host.services().next_rudi_packet_id; CHECK(next_packet>0);
    pair.source.close(); CHECK(!pair.source.queued_fragments());
    Endpoint replacement(1,pair.source_host,pair.loop,pair.trace,64);
    replacement.memory().add_job(1); pair.forward.release(); replacement.submit(pair.write());
    pair.loop.run_until(50000);
    Completion completion{}; CHECK(replacement.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(pair.source_host.services().next_rudi_packet_id>next_packet && !replacement.leased_message_ids());
    CHECK(!replacement.poll_completion(completion)); replacement.close(); CHECK(!pair.close());
}
static void source_id_exhaustion_is_terminal_without_wrap() {
    RudiPair pair; pair.source_host.services().next_rudi_packet_id=UINT32_MAX;
    pair.source.submit(pair.write()); pair.loop.run_until(1000);
    Completion completion{}; CHECK(pair.source.poll_completion(completion) && completion.status==CompletionStatus::ResourceExhausted);
    CHECK(pair.source_host.services().next_rudi_packet_id==uint64_t{UINT32_MAX}+1 && !pair.forward.transmissions);
    CHECK(!pair.source.pending() && !pair.source.leased_message_ids()); CHECK(!pair.close());
}
static void host_close_cancels_transport_timers() {
    // Drop after source departure. There are live transport timers, but no
    // independent in-flight Fabric serialization events to confuse with them.
    RudiPair pair; pair.forward.discard=true;
    pair.source.submit(pair.write()); pair.loop.run_until(1000);
    CHECK(pair.source.pending()); pair.source_host.close(); pair.source.close();
    Completion completion{}; CHECK(pair.source.poll_completion(completion) && completion.status==CompletionStatus::Cancelled);
    CHECK(!pair.close());
}
int main() {
    try {
        retry_exhaustion_repeats_only_idempotent_writes(); cancel_backpressured_source(false); cancel_backpressured_source(true);
        returned_data_never_rebinds_a_reused_key(); endpoint_replacement_preserves_packet_identity();
        source_id_exhaustion_is_terminal_without_wrap(); host_close_cancels_transport_timers();
        std::cout<<"PASS7 RUDI retry exhaustion, cancellation/deadline, backpressure, MR identity, FEP replacement, ID exhaustion and close\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
