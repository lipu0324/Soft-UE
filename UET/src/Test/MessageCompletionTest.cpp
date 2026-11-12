#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

class DelayedEndPort : public IPacketPort {
public:
    DelayedEndPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_header.Standard_Header.eom && loop_.now()<10*kMillisecond) {
            loop_.at(10*kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; EventLoop& loop_;
};

// Independently generate the per-packet DEFAULT_RESPONSE used by other SES
// implementations. An intermediate response is not a message completion.
class DefaultResponsePort : public IPacketPort {
public:
    explicit DefaultResponsePort(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        auto& packet=decoded.packet;
        if (packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_NONE) {
            packet.PDS_header.RUOD_ack_header.next_hdr=UET_HDR_RESPONSE;
            packet.SESpkt.bth_type=Semantic_Response_Header;
            auto& response=packet.SESpkt.bth_header.Semantic_Response_Header;
            response.opcode=0; response.return_code=1; response.message_id=1; response.job_id=1;
            Frame changed=frame; changed.bytes=UetWireCodec::encode(packet,decoded.network);
            ++default_responses;
            return lower_.try_send(changed);
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    size_t default_responses=0;
private:
    IPacketPort& lower_;
};

void completion_waits_for_end(bool reject_key) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    DelayedEndPort delayed(forward,loop); DefaultResponsePort defaults(reverse);
    PdsHost source_host(1,loop,trace,delayed),target_host(2,loop,trace,defaults);
    source_host.services().rto_ms=20;
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,512,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=reject_key?0:region.key;
    write.payload.assign(256,0x5a); source.submit(write);
    const auto run_until=[&](Time limit) {
        try { loop.run_until(limit,5000); }
        catch (...) {
            const auto start=trace.events().size()>30?trace.events().size()-30:0;
            for (size_t index=start;index<trace.events().size();++index) {
                const auto& event=trace.events()[index];
                std::cerr<<event.time<<' '<<event.node<<' '<<event.event<<' '<<event.value<<'\n';
            }
            throw;
        }
    };
    run_until(kMillisecond);
    Completion completion{};
    if (reject_key) {
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError);
        CHECK(source.leased_message_ids()==1); // Unsent/uncleared fragments still own this ID.
    } else {
        CHECK(defaults.default_responses>0);
        CHECK(!source.poll_completion(completion));
        CHECK(target.memory().read(1,1,region.key,255,1)[0]==0);
    }
    run_until(11*kMillisecond);
    if (!reject_key) {
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.length==256);
        CHECK(target.memory().read(1,1,region.key,0,256)==write.payload);
    } else CHECK(target.memory().read(1,1,region.key,0,256)==std::vector<uint8_t>(256,0));
    CHECK(!source.poll_completion(completion) && source.leased_message_ids()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        completion_waits_for_end(false); completion_waits_for_end(true);
        std::cout<<"PASS: intermediate DEFAULT_RESPONSE cannot complete a message; failed IDs stay leased through EOM\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
