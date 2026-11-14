#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

enum class CloseLoss { Tail, ErrorAcknowledgment };
struct CloseRecoveryObservation {
    std::optional<uint32_t> tail_psn;
    size_t attempts=0;
    bool dropped=false;
};
class CloseLossPort final : public IPacketPort {
public:
    CloseLossPort(IPacketPort& lower,EventLoop& loop,CloseRecoveryObservation& observation,bool source,CloseLoss loss)
        :lower_(lower),loop_(loop),observation_(observation),source_(source),loss_(loss) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        bool discard=false;
        if (source_ && packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            packet.SESpkt.bth_header.Standard_Header.opcode==0x0f) {
            observation_.tail_psn=static_cast<uint32_t>(packet.PDS_header.RUOD_req_header.psn); ++observation_.attempts;
            discard=loss_==CloseLoss::Tail;
        } else if (!source_ && loss_==CloseLoss::ErrorAcknowledgment && observation_.tail_psn &&
            packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header) {
            const auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
            discard=acknowledgment.cack_psn+acknowledgment.ack_psn_off==*observation_.tail_psn &&
                packet.SESpkt.bth_header.Semantic_Response_Header.return_code==static_cast<uint8_t>(SemanticReturnCode::InitiatorError);
        }
        if (discard && !observation_.dropped) {
            observation_.dropped=true;
            if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
            return SendResult::Accepted; // Loss after MAC departure preserves the real PDS RTO boundary.
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver handler) override { lower_.set_receiver(std::move(handler)); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
private:
    IPacketPort& lower_; EventLoop& loop_; CloseRecoveryObservation& observation_; bool source_; CloseLoss loss_;
};
static void recovery(pdc_mode mode,CloseLoss loss) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42); CloseRecoveryObservation observation;
    CloseLossPort forward(fabric.add_host(1),loop,observation,true,loss),reverse(fabric.add_host(2),loop,observation,false,loss);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.services().psn_ranges.local_packet_capacity=1;
    Endpoint previous(1,source_host,loop,trace,128,100*kMillisecond,nullptr,1);
    Endpoint target(2,target_host,loop,trace,128,100*kMillisecond,nullptr,8,1);
    previous.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,4096,7);
    size_t reader_calls=0;
    Operation operation; operation.type=OperationType::Write; operation.delivery_mode=mode;
    operation.peer=2; operation.remote_key=region.key;
    operation.payload_source=std::make_shared<GeneratedPayload>(4096,[&](uint64_t,uint8_t* bytes,size_t count) {
        ++reader_calls; std::memset(bytes,0x66,count);
    });
    previous.submit(operation); loop.run_until(1); CHECK(reader_calls && reader_calls*128<4096);
    const auto copied_fragments=reader_calls; previous.close(); Completion completion{};
    CHECK(previous.poll_completion(completion) && completion.status==CompletionStatus::Cancelled);
    Endpoint replacement(1,source_host,loop,trace,128); replacement.memory().add_job(1);
    Operation next; next.type=OperationType::Noop; next.delivery_mode=mode; next.peer=2;
    replacement.submit(next); loop.run_until(20*kMillisecond);
    CHECK(observation.dropped && observation.attempts>=2 && reader_calls==copied_fragments);
    CHECK(replacement.poll_completion(completion) && completion.status==CompletionStatus::Success && !replacement.poll_completion(completion));
    CHECK(!target.poll_completion(completion) && !target.retained_receive_messages() && !source_host.services().retired_semantic_messages.size());
    std::vector<uint8_t> expected(4096); std::fill_n(expected.begin(),copied_fragments*128,0x66);
    CHECK(target.memory().read(1,1,region.key,0,4096)==expected);
    replacement.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (auto loss:{CloseLoss::Tail,CloseLoss::ErrorAcknowledgment}) recovery(mode,loss);
        std::cout<<"PASS4 closed-Endpoint MSG_ERROR and guaranteed error-ACK loss recover through original PDS\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
