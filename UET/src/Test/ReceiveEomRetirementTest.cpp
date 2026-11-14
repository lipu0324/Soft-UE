#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

// Delay SOM so EOM is received first, then hold actual generated Clear CPs.
// A rewritten legal partial Clear traverses the real wire/PDS receive path.
class PartialClearPort final : public IPacketPort {
public:
    PartialClearPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Clear_cmd) {
            if (!clear_frame) clear_frame=frame;
            return SendResult::Accepted;
        }
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            if (header.eom) end_sequence=packet.PDS_header.RUOD_req_header.psn;
            if (header.som && !delayed) {
                delayed=true; first_sequence=packet.PDS_header.RUOD_req_header.psn;
                loop_.after(kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
                return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void clear_through(uint32_t sequence) {
        CHECK(clear_frame); auto decoded=UetWireCodec::decode(clear_frame->bytes.data(),clear_frame->bytes.size());
        decoded.packet.PDS_header.RUOD_cp_header.payload=sequence;
        auto frame=*clear_frame; frame.bytes=UetWireCodec::encode(decoded.packet,decoded.network);
        CHECK(lower_.try_send(frame)==SendResult::Accepted);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    std::optional<Frame> clear_frame;
    uint32_t first_sequence=0,end_sequence=0;
private:
    IPacketPort& lower_; EventLoop& loop_; bool delayed=false;
};

void keeps_actual_end(OperationType type) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    PartialClearPort forward(fabric.add_host(1),loop); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.services().rto_ns=20*kMillisecond; target_host.services().rto_ns=20*kMillisecond;
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,64,7);
    if (type==OperationType::Send) target.post_receive(1,1,region.key,0,64,77);
    if (type==OperationType::TaggedSend) target.post_tagged_receive(1,1,region.key,0,64,{0x1234,0,{}},77);
    Operation operation; operation.type=type; operation.delivery_mode=RUD; operation.peer=2;
    operation.remote_key=region.key; operation.tag=0x1234; operation.payload.assign(48,0xa5);
    source.submit(operation); loop.run_until(2*kMillisecond);
    CHECK(target.memory().read(1,1,region.key,0,48)==operation.payload);
    CHECK(forward.end_sequence-forward.first_sequence==2 && forward.clear_frame && target.retained_receive_messages()==1);
    forward.clear_through(forward.first_sequence); loop.run_until(3*kMillisecond);
    // The last placed fragment was SOM. Clear of SOM must not retire the
    // message before the actual EOM (two PSNs later) is cleared.
    if (target.retained_receive_messages()!=1)
        std::cerr<<"Premature retirement opcode="<<unsigned(type)<<" first="<<forward.first_sequence<<" EOM="<<forward.end_sequence<<'\n';
    CHECK(target.retained_receive_messages()==1);
    forward.clear_through(forward.end_sequence); loop.run_until(4*kMillisecond);
    CHECK(!target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (const auto type:{OperationType::Write,OperationType::Send,OperationType::TaggedSend}) keeps_actual_end(type);
        std::cout<<"PASS RUD WRITE/SEND/tagged message records survive partial Clear until their actual EOM\n";
    }
    catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
