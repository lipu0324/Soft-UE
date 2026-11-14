#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include "../SES/SemanticRequestFields.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

struct TargetReplacementObservation {
    bool drop_first_result=false,drop_first_ack=false,result_dropped=false,ack_dropped=false,block_new_results=false;
    std::optional<uint32_t> first_reverse_psn;
    std::map<uint32_t,uint16_t> read_ordinals;
    uint16_t next_ordinal=0;
    size_t resource_refusals=0;
    std::optional<uint16_t> last_wire_response_token;
};
class TargetReplacementPort final : public IPacketPort {
public:
    TargetReplacementPort(IPacketPort& lower,EventLoop& loop,TargetReplacementObservation& state,bool source)
        :lower_(lower),loop_(loop),state_(state),source_(source) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        bool discard=false;
        if (!source_ && packet.PDS_type==nack_header && packet.PDS_header.nack_header.nack_code==UET_NO_SES_MSG_AVAIL)
            ++state_.resource_refusals;
        if (source_ && packet.PDS_type==RUOD_req_header) {
            const auto fields=semantic_request_fields(packet.SESpkt);
            if (fields && fields->header.opcode==2) {
                const uint32_t sequence=packet.PDS_header.RUOD_req_header.psn;
                if (!state_.read_ordinals.count(sequence)) state_.read_ordinals.emplace(sequence,++state_.next_ordinal);
            }
        }
        if (!source_ && packet.PDS_type==RUOD_req_header &&
            (packet.SESpkt.bth_type==Semantic_Response_with_Data_Header || packet.SESpkt.bth_type==Optimized_Response_with_Data_Header)) {
            const uint16_t ordinal=packet.SESpkt.bth_type==Semantic_Response_with_Data_Header?
                packet.SESpkt.bth_header.Semantic_Response_with_Data_Header.read_request_msg_id:
                state_.read_ordinals.at(packet.SESpkt.bth_header.Optimized_Response_with_Data_Header.original_request_psn);
            if (packet.SESpkt.bth_type==Semantic_Response_with_Data_Header)
                state_.last_wire_response_token=static_cast<uint16_t>(packet.SESpkt.bth_header.Semantic_Response_with_Data_Header.response_message_id);
            if (ordinal==1 && !state_.first_reverse_psn)
                state_.first_reverse_psn=static_cast<uint32_t>(packet.PDS_header.RUOD_req_header.psn);
            if (ordinal>=3 && state_.block_new_results) return SendResult::WouldBlock;
            if (state_.drop_first_result && !state_.result_dropped) { state_.result_dropped=true; discard=true; }
        }
        if (source_ && state_.drop_first_ack && !state_.ack_dropped && state_.first_reverse_psn && packet.PDS_type==RUOD_ack_header) {
            const auto& header=packet.PDS_header.RUOD_ack_header;
            if (header.cack_psn+header.ack_psn_off==*state_.first_reverse_psn) { state_.ack_dropped=true; discard=true; }
        }
        if (discard) {
            if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { writable_=callback; lower_.set_writable_handler(std::move(callback)); }
    void release() { state_.block_new_results=false; if (writable_) writable_(); }
private:
    IPacketPort& lower_; EventLoop& loop_; TargetReplacementObservation& state_; bool source_; Writable writable_;
};
struct TargetReplacementPair {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42}; TargetReplacementObservation state;
    TargetReplacementPort forward{fabric.add_host(1),loop,state,true},reverse{fabric.add_host(2),loop,state,false};
    PdsHost source_host{1,loop,trace,forward},target_host{2,loop,trace,reverse};
    MemoryRegistry domain;
    Endpoint source{1,source_host,loop,trace,64};
    std::unique_ptr<Endpoint> target;
    Region remote,local;
    RequestHeaderFormat format;
    pdc_mode mode;
    TargetReplacementPair(RequestHeaderFormat selected,pdc_mode delivery):format(selected),mode(delivery) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source_host.configure_read_ack_data(0); target_host.configure_read_ack_data(0);
        source_host.configure_retry_limit(15); target_host.services().psn_ranges.local_packet_capacity=1;
        source.memory().add_job(1); domain.add_job(1);
        RegionOptions options; if (format==RequestHeaderFormat::Small) options.requested_key=MemoryKeyFormat::Optimized|3;
        remote=domain.register_region(1,1,64,7,options); local=source.memory().register_region(1,1,64,7);
        remote.storage->write(0,std::vector<uint8_t>(64,0x55).data(),64); replace_target();
    }
    void replace_target(size_t response_limit=8) {
        target=std::make_unique<Endpoint>(2,target_host,loop,trace,64,100*kMillisecond,&domain,8,4096,256*1024,response_limit);
        if (format==RequestHeaderFormat::Small) target->resources().configure_resource(1,3,ResourceSpace::Rma);
    }
    uint64_t submit_read(unsigned index) {
        Operation operation; operation.type=OperationType::Read; operation.header_format=format; operation.delivery_mode=mode;
        operation.peer=2; operation.remote_key=remote.key; operation.remote_offset=index*8; operation.read_length=8;
        operation.read_result=ReadResultBuffer{local.key,uint64_t{index}*16,8,1,1}; return source.submit(operation);
    }
    void close() { source.close(); target->close(); source_host.close(); target_host.close(); loop.run_until(20*kMillisecond); CHECK(!loop.pending()); }
};
static void accepted_read_has_a_terminal_result(RequestHeaderFormat format,pdc_mode mode) {
    TargetReplacementPair pair(format,mode); pair.state.drop_first_result=true;
    const auto id=pair.submit_read(0); pair.loop.run_until(20000);
    CHECK(pair.state.result_dropped && pair.target->pending_read_returns()==1);
    pair.target->close(); pair.loop.run_until(3*kMillisecond);
    Completion completion{};
    if (!pair.source.poll_completion(completion))
        throw std::runtime_error("closed target lost the owner of an accepted READ receive handle");
    CHECK(completion.operation==id && (completion.status==CompletionStatus::Success || completion.status==CompletionStatus::RemoteError));
    CHECK(!pair.source.poll_completion(completion)); pair.close();
}
static void old_response_token_cannot_retire_new_read(RequestHeaderFormat format,pdc_mode mode,bool force_wrap) {
    TargetReplacementPair pair(format,mode); pair.state.drop_first_ack=true;
    // Script only source semantic callbacks so a target-close error cannot
    // close the shared PDC before this independent target-token test finishes.
    // Actual requests, return data, ACKs, PSNs and recovery still use PDS.
    pair.source_host.set_response_handler([](const PDC_SES_rsp&) {});
    pair.submit_read(0); pair.submit_read(1); pair.loop.run_until(20000);
    CHECK(pair.state.ack_dropped && pair.target->pending_read_returns()==2);
    pair.target->close(); pair.replace_target(); pair.state.block_new_results=true;
    if (force_wrap) pair.target_host.services().semantic_response_cursor=UINT16_MAX;
    pair.submit_read(2); pair.submit_read(3); pair.loop.run_until(3*kMillisecond);
    if (pair.target->pending_read_returns()!=2 || pair.target->retained_read_packets()!=2)
        throw std::runtime_error("old return-data token retired a new READ before its data was acknowledged");
    pair.reverse.release(); pair.loop.run_until(10*kMillisecond);
    CHECK(!pair.target->pending_read_returns() && !pair.target->retained_read_packets()); pair.close();
}
static void read_credit_includes_retired_responses() {
    TargetReplacementPair pair(RequestHeaderFormat::Standard,RUD); pair.state.drop_first_ack=true;
    pair.source_host.set_response_handler([](const PDC_SES_rsp&) {});
    pair.submit_read(0); pair.submit_read(1); pair.loop.run_until(20000);
    CHECK(pair.target->pending_read_returns()==2);
    pair.target->close(); pair.replace_target(2); pair.state.block_new_results=true;
    pair.submit_read(2); pair.loop.run_until(100000);
    CHECK(pair.state.resource_refusals && !pair.target->pending_read_returns() && !pair.target->retained_read_packets());
    CHECK(pair.target_host.services().retired_semantic_responses.size()==2);
    pair.reverse.release(); pair.loop.run_until(10*kMillisecond);
    CHECK(!pair.target->pending_read_returns() && !pair.target_host.services().retired_semantic_responses.size()); pair.close();
}
static void response_allocator_wrap_skips_retired_tokens() {
    TargetReplacementPair pair(RequestHeaderFormat::Standard,RUD);
    pair.target->close(); pair.replace_target(UINT16_MAX);
    // Model an old, independent peer retaining every token except5. The new
    // real wire transaction must select5 after wrap, not alias another peer.
    for (uint32_t token=1;token<=UINT16_MAX;++token) if (token!=5)
        pair.target_host.services().retired_semantic_responses.retain(static_cast<uint16_t>(token),{3,1,513,17,0,false});
    pair.target_host.services().semantic_response_cursor=UINT16_MAX;
    const auto id=pair.submit_read(0); pair.loop.run_until(3*kMillisecond); Completion completion{};
    CHECK(pair.state.last_wire_response_token==5 && pair.target_host.services().semantic_response_cursor==5);
    CHECK(pair.source.poll_completion(completion) && completion.operation==id && completion.status==CompletionStatus::Success);
    CHECK(pair.target_host.services().retired_semantic_responses.size()==UINT16_MAX-1); pair.close();
}
int main(int argc,char** argv) {
    try {
        const bool token_only=argc>1 && std::string(argv[1])=="--token";
        for (auto format:{RequestHeaderFormat::Standard,RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD}) {
            if (!token_only) accepted_read_has_a_terminal_result(format,mode);
            for (bool force_wrap:{false,true}) old_response_token_cannot_retire_new_read(format,mode,force_wrap);
        }
        read_credit_includes_retired_responses(); response_allocator_wrap_skips_retired_tokens();
        std::cout<<"PASS20 target Endpoint READ ownership and old/new response-token isolation\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
