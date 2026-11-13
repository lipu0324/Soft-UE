#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

struct SendScenario {
    pdc_mode mode=ROD;
    bool ipv6=false,udp=false,deferrable=false,late_posting=false,unmatched=false,poisoned=false,delay_som=false;
    uint64_t header_data=0;
    size_t bytes=33;
};

class DeferrableWirePort final : public IPacketPort {
public:
    DeferrableWirePort(IPacketPort& lower,EventLoop& loop,const SendScenario& scenario):lower_(lower),loop_(loop),scenario_(scenario) {}
    SendResult try_send(const Frame& frame) override {
        auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        auto& packet=decoded.packet;
        if (packet.PDS_type!=RUOD_req_header && packet.PDS_type!=UUD_req_header) return lower_.try_send(frame);
        auto& semantic=packet.SESpkt.bth_header.Standard_Header;
        if (scenario_.deferrable && semantic.opcode==static_cast<uint8_t>(OperationType::Send)) {
            semantic.opcode=0x08;
            // §3.4.4.6.1: upper half is an initiator restart token; initial
            // target token is zero. Treat-as-SEND must never use this as offset.
            semantic.buffer_offset=0xfedcba9800000000ULL;
            ++deferrable_packets;
        }
        if (scenario_.poisoned && semantic.som) semantic.ie=1;
        Frame changed=frame; changed.bytes=UetWireCodec::encode(packet,decoded.network);
        if (scenario_.delay_som && semantic.som && loop_.now()<2*kMillisecond) {
            loop_.at(2*kMillisecond,[this,changed] { CHECK(lower_.try_send(changed)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        return lower_.try_send(changed);
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    size_t deferrable_packets=0;
private:
    IPacketPort& lower_; EventLoop& loop_; SendScenario scenario_;
};

void transfer(const SendScenario& scenario) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    DeferrableWirePort source_port(forward,loop,scenario);
    WireOptions wire; wire.ipv6=scenario.ipv6; wire.udp=scenario.udp;
    PdsHost source_host(1,loop,trace,source_port,PdsHost::WireFormat::Uet11,wire);
    PdsHost target_host(2,loop,trace,reverse,PdsHost::WireFormat::Uet11,wire);
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(0); target.memory().add_job(0);
    const auto region=target.memory().register_region(0,1,128,7);
    if (!scenario.late_posting && !scenario.unmatched) target.post_receive(0,1,region.key,7,64,123);
    Operation send; send.type=scenario.mode==UUD?OperationType::DatagramSend:OperationType::Send;
    send.delivery_mode=scenario.mode; send.peer=2; send.job=0;
    send.immediate_data=scenario.header_data; send.payload.assign(scenario.bytes,0x5a);
    auto operation=source.submit(send);
    loop.run_until(kMillisecond);
    Completion completion{};
    if (scenario.delay_som) {
        CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
        loop.run_until(5*kMillisecond,100000);
    }
    if (scenario.late_posting) {
        if (scenario.deferrable) {
            CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError);
            CHECK(completion.remote_code==static_cast<uint8_t>(SemanticReturnCode::NoMatch) && completion.length==0);
            CHECK(target.unexpected_bytes()==0 && !target.poll_completion(completion));
        } else CHECK(!source.poll_completion(completion) && target.unexpected_bytes()==scenario.bytes);
        target.post_receive(0,1,region.key,7,64,123);
        if (scenario.deferrable) operation=source.submit(send); // Explicit new-message retry after NoMatch.
        loop.run_until(5*kMillisecond,100000);
    }
    CHECK(source.poll_completion(completion) && completion.operation==operation);
    const bool remote_error=scenario.unmatched || scenario.poisoned;
    CHECK(completion.status==(scenario.mode==UUD?CompletionStatus::LocalSuccess:
        remote_error?CompletionStatus::RemoteError:CompletionStatus::Success));
    CHECK(!source.poll_completion(completion));
    if (scenario.unmatched) CHECK(!target.poll_completion(completion));
    else {
        CHECK(target.poll_completion(completion) && completion.receive && completion.context==123);
        CHECK(completion.status==(scenario.poisoned?CompletionStatus::RemoteError:CompletionStatus::Success));
        CHECK(completion.immediate_data==std::optional<uint64_t>{scenario.header_data});
        CHECK(!target.poll_completion(completion)); // Exactly one CQ entry for the one posting.
    }
    const auto expected=remote_error?std::vector<uint8_t>(scenario.bytes,0):send.payload;
    CHECK(target.memory().read(0,1,region.key,7,scenario.bytes)==expected);
    CHECK(target.memory().read(0,1,region.key,0,7)==std::vector<uint8_t>(7,0));
    CHECK(target.memory().read(0,1,region.key,7+scenario.bytes,128-7-scenario.bytes)==std::vector<uint8_t>(128-7-scenario.bytes,0));
    if (scenario.deferrable) {
        CHECK(source_port.deferrable_packets>0);
        const auto fallback_events=std::count_if(trace.events().begin(),trace.events().end(),[](const auto& event) {
            return event.node==2 && event.event=="deferrable_as_send";
        });
        CHECK(fallback_events==(scenario.late_posting?2:1));
    }
    // Idle Clear must retire error tails without another application request.
    CHECK(source.leased_message_ids()==0 && target.retained_receive_messages()==0);
    if (scenario.mode==UUD) {
        CHECK(fabric.stats(2,1).packets==0);
        CHECK(source_host.manager().getPDSStatus().open_cnt==0 && target_host.manager().getPDSStatus().open_cnt==0);
    }
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{ROD,RUD,UUD}) for (bool ipv6:{false,true}) for (bool udp:{false,true}) {
            SendScenario scenario; scenario.mode=mode; scenario.ipv6=ipv6; scenario.udp=udp;
            if (mode==UUD) scenario.bytes=16;
            for (const uint64_t header_data:{uint64_t{0},UINT64_MAX}) {
                scenario.header_data=header_data; transfer(scenario);
                if (mode!=UUD) { scenario.deferrable=true; transfer(scenario); scenario.deferrable=false; }
            }
        }
        for (bool deferrable:{false,true}) {
            SendScenario late; late.deferrable=deferrable; late.late_posting=true; late.header_data=0x123456789abcdef0ULL;
            transfer(late);
            SendScenario unmatched; unmatched.mode=RUD; unmatched.deferrable=deferrable; unmatched.unmatched=true;
            unmatched.header_data=123; transfer(unmatched);
            SendScenario poisoned; poisoned.deferrable=deferrable; poisoned.poisoned=true; poisoned.bytes=8;
            poisoned.header_data=0x9988776655443322ULL; transfer(poisoned);
        }
        SendScenario zero; zero.bytes=0; zero.header_data=0; transfer(zero);
        zero.deferrable=true; transfer(zero);
        SendScenario reordered; reordered.mode=RUD; reordered.deferrable=true; reordered.delay_som=true;
        reordered.header_data=0x1020304050607080ULL; transfer(reordered);
        std::cout<<"PASS SEND/DGRAM CQ data, deferrable-as-SEND tokens, late posting, no-match, IE and zero-length boundaries\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
