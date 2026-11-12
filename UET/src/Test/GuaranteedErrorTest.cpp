#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <map>
#include <set>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

// These ports only inject loss/reordering and inspect actual wire flags. The
// original PDS kernel remains responsible for replay, ACK Request and Clear.
class DelayedStartPort final : public IPacketPort {
public:
    DelayedStartPort(IPacketPort& lower,EventLoop& loop,bool delay_start)
        :lower_(lower),loop_(loop),delay_start_(delay_start) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
            const auto& request=packet.SESpkt.bth_header.Standard_Header;
            if (request.som && !first_sequence) first_sequence=packet.PDS_header.RUOD_req_header.psn;
            if (first_sequence && packet.PDS_header.RUOD_req_header.psn==*first_sequence) ++first_data_attempts;
            if (delay_start_ && request.som) {
                delay_start_=false;
                loop_.at(200000,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
                return SendResult::Accepted;
            }
        }
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==ACK_req)
            ++response_queries;
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    std::optional<uint32_t> first_sequence;
    size_t response_queries=0,first_data_attempts=0;
private:
    IPacketPort& lower_; EventLoop& loop_; bool delay_start_;
};

class ErrorAuditPort final : public IPacketPort {
public:
    enum class Loss { None, FirstGuaranteed, FirstGuaranteedAndRepeated };
    ErrorAuditPort(IPacketPort& lower,Loss loss):lower_(lower),loss_(loss) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE) {
            const auto& semantic=packet.SESpkt.bth_header.Semantic_Response_Header;
            const auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
            if (semantic.return_code!=1 && semantic.opcode==1) {
                const uint32_t sequence=acknowledgment.cack_psn+acknowledgment.ack_psn_off;
                const bool guaranteed=(acknowledgment.flags.req&1)!=0;
                CHECK(semantic.return_code==0x1c); // RC_BAD_MEMORY_KEY remains sticky.
                if (!first_error_sequence) first_error_sequence=sequence;
                error_sequences.insert(sequence);
                if (guaranteed) guaranteed_sequences.insert(sequence);
                else ++best_effort_errors;
                if ((guaranteed && loss_!=Loss::None && !dropped_first_guaranteed) ||
                    (!guaranteed && loss_==Loss::FirstGuaranteedAndRepeated)) {
                    if (guaranteed) dropped_first_guaranteed=true;
                    return SendResult::Accepted;
                }
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    std::optional<uint32_t> first_error_sequence;
    std::set<uint32_t> error_sequences,guaranteed_sequences;
    size_t best_effort_errors=0;
    bool dropped_first_guaranteed=false;
private:
    IPacketPort& lower_; Loss loss_;
};

void first_error_owns_guarantee(pdc_mode mode,bool congestion,ErrorAuditPort::Loss loss,bool delay_start) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    DelayedStartPort requests(forward,loop,delay_start); ErrorAuditPort responses(reverse,loss);
    PdsHost source_host(1,loop,trace,requests),target_host(2,loop,trace,responses);
    source_host.services().rto_ns=kMillisecond;
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,256);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    Operation write; write.type=OperationType::Write; write.peer=2; write.delivery_mode=mode;
    write.remote_key=0; write.payload.assign(512,7);
    const auto operation=source.submit(write);
    loop.run_until(500000);
    Completion completion{};
    if (loss==ErrorAuditPort::Loss::FirstGuaranteedAndRepeated) CHECK(!source.poll_completion(completion));
    loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.operation==operation &&
        completion.status==CompletionStatus::RemoteError && completion.remote_code==0x1c);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK(responses.error_sequences.size()==8 && responses.guaranteed_sequences.size()==1);
    CHECK(responses.first_error_sequence && *responses.guaranteed_sequences.begin()==*responses.first_error_sequence);
    CHECK(responses.best_effort_errors>=7 && requests.first_sequence);
    CHECK(*responses.first_error_sequence==*requests.first_sequence+(delay_start?1:0));
    if (loss!=ErrorAuditPort::Loss::None) {
        CHECK(responses.dropped_first_guaranteed);
        CHECK(requests.response_queries>0 || requests.first_data_attempts>1);
    }
    if (loss==ErrorAuditPort::Loss::FirstGuaranteed && mode==RUD && congestion)
        CHECK(requests.response_queries>0); // SACK reports receipt, but not the missing error's semantics.
    CHECK(source.leased_message_ids()==0);
    // Non-guaranteed tail responses do not request a standalone Clear. The
    // next data request carries the source's cumulative Clear (§3.5.16.3),
    // which retires the previous message without an extra error guarantee.
    CHECK(target.retained_receive_messages()<=1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2; noop.delivery_mode=mode;
    const auto next_operation=source.submit(noop); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.operation==next_operation && completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion) && source.leased_message_ids()==0 && target.retained_receive_messages()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true})
            for (const auto loss:{ErrorAuditPort::Loss::None,ErrorAuditPort::Loss::FirstGuaranteed,
                                  ErrorAuditPort::Loss::FirstGuaranteedAndRepeated})
                first_error_owns_guarantee(mode,congestion,loss,false);
        for (const auto loss:{ErrorAuditPort::Loss::None,ErrorAuditPort::Loss::FirstGuaranteedAndRepeated})
            first_error_owns_guarantee(RUD,false,loss,true);
        std::cout<<"PASS first-error guarantee, repeated errors, loss/query/Clear and RUD encounter order\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
