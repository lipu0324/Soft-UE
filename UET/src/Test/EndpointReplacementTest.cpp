#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include "../SES/SemanticRequestFields.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class OldEndpointLossPort final : public IPacketPort {
public:
    OldEndpointLossPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        const auto fields=semantic_request_fields(packet.SESpkt);
        if (packet.PDS_type==RUOD_req_header && fields && fields->header.opcode==1 &&
            packet.SESpkt.payload==std::vector<uint8_t>{0xaa}) {
            ++old_attempts;
            if (!lose_old) return lower_.try_send(frame);
            if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver handler) override { lower_.set_receiver(std::move(handler)); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
    size_t old_attempts=0;
    bool lose_old=true;
private:
    IPacketPort& lower_; EventLoop& loop_;
};
static void replacement_isolation(RequestHeaderFormat format,bool lose_old,bool force_wrap) {
        EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
        OldEndpointLossPort forward(fabric.add_host(1),loop); auto& reverse=fabric.add_host(2);
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
        source_host.configure_retry_limit(15);
        Endpoint previous(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
        previous.memory().add_job(1); target.memory().add_job(1);
        RegionOptions options;
        if (format==RequestHeaderFormat::Small) {
            options.requested_key=MemoryKeyFormat::Optimized|3;
            target.resources().configure_resource(1,3,ResourceSpace::Rma);
        }
        const auto region=target.memory().register_region(1,1,32,7,options);
        forward.lose_old=lose_old;
        Operation operation; operation.type=OperationType::Write; operation.delivery_mode=RUD;
        operation.header_format=format; operation.peer=2; operation.remote_key=region.key; operation.payload={0xaa}; operation.context=11;
        previous.submit(operation);
        // Close before the host pumps its queued SES request. A new Endpoint
        // must not adopt the old request's late PDC transmission/ACK events.
        previous.close(); Completion completion{};
        if (force_wrap) source_host.services().semantic_message_cursor=UINT16_MAX;
        CHECK(previous.poll_completion(completion) && completion.status==CompletionStatus::Cancelled && completion.context==11);
        Endpoint replacement(1,source_host,loop,trace,128,3*kMillisecond);
        replacement.memory().add_job(1);
        operation.payload={0xbb}; operation.remote_offset=8; operation.context=22;
        const auto id=replacement.submit(operation); loop.run_until(5*kMillisecond);
        CHECK(forward.old_attempts && target.memory().read(1,1,region.key,8,1,format==RequestHeaderFormat::Small?3:1)==std::vector<uint8_t>{0xbb});
        CHECK(replacement.poll_completion(completion));
        if (completion.status!=CompletionStatus::Success)
            throw std::runtime_error("new Endpoint adopted old request state: status="+std::to_string(unsigned(completion.status)));
        CHECK(completion.operation==id && completion.context==22 && !replacement.poll_completion(completion));
        CHECK(source_host.services().retired_semantic_messages.size()==size_t(lose_old));
        replacement.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

static void active_binding_is_exclusive() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    bool rejected=false;
    try { Endpoint concurrent(1,source_host,loop,trace); } catch (const std::logic_error&) { rejected=true; }
    CHECK(rejected);
    Operation operation; operation.type=OperationType::Noop; operation.peer=2;
    source.submit(operation); loop.run_until(kMillisecond); Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    source.close();
    Endpoint replacement(1,source_host,loop,trace); replacement.memory().add_job(1);
    replacement.submit(operation); loop.run_until(2*kMillisecond);
    CHECK(replacement.poll_completion(completion) && completion.status==CompletionStatus::Success);
    replacement.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
static void exhausted_retired_namespace_is_explicit() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42); auto& port=fabric.add_host(1);
    PdsHost host(1,loop,trace,port); Endpoint source(1,host,loop,trace); source.memory().add_job(1);
    for (uint32_t message=1;message<=UINT16_MAX;++message)
        host.services().retired_semantic_messages.retain(static_cast<uint16_t>(message),{2,1});
    Operation operation; operation.type=OperationType::Noop; operation.peer=2;
    source.submit(operation); Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::ResourceExhausted);
    CHECK(!source.pending() && !source.queued_fragments() && !host.manager().getPDSStatus().open_cnt);
    source.close(); host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto format:{RequestHeaderFormat::Standard,RequestHeaderFormat::Small,RequestHeaderFormat::Medium})
            for (bool loss:{false,true}) for (bool force_wrap:{false,true}) replacement_isolation(format,loss,force_wrap);
        active_binding_is_exclusive(); exhausted_retired_namespace_is_explicit();
        std::cout<<"PASS14 Endpoint replacement isolates old queued PDC work, cursor wrap/exhaustion, lease retirement and exclusive host binding\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
