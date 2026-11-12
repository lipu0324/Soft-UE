#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

// Faults alter the semantic request before it enters the target kernel. PDS
// still allocates PSNs, retransmits, deduplicates and clears every packet.
class SemanticFaultPort : public IPacketPort {
public:
    enum class Fault { None, DelayTail, InitiatorError, EarlyMessageError };
    SemanticFaultPort(IPacketPort& lower,EventLoop& loop,Fault fault):lower_(lower),loop_(loop),fault_(fault) {}
    SendResult try_send(const Frame& frame) override {
        auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        auto& packet=decoded.packet;
        if (packet.PDS_type!=RUOD_req_header || packet.SESpkt.bth_type!=Standard_Header)
            return lower_.try_send(frame);
        auto& header=packet.SESpkt.bth_header.Standard_Header;
        if (header.msg_id!=1) return lower_.try_send(frame);
        first_pdc=packet.PDS_header.RUOD_req_header.spdcid;
        if (header.opcode==0x0f) ++aborts;
        const auto offset=header.som?0:header.diff.som_false.message_offset;
        if (fault_==Fault::InitiatorError && offset==16) header.ie=1;
        if (fault_==Fault::EarlyMessageError && header.eom) {
            header.opcode=0x0f; packet.SESpkt.payload.clear();
            header.diff.som_false.payload_length=0;
        }
        Frame changed=frame; changed.bytes=UetWireCodec::encode(packet,decoded.network);
        const bool delayed=(fault_==Fault::DelayTail && !header.som) ||
            ((fault_==Fault::InitiatorError || fault_==Fault::EarlyMessageError) && header.som) ||
            (fault_==Fault::EarlyMessageError && !header.eom);
        if (delayed && loop_.now()<5*kMillisecond) {
            loop_.at(5*kMillisecond,[this,changed] { CHECK(lower_.try_send(changed)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        return lower_.try_send(changed);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    size_t aborts=0;
    uint16_t first_pdc=0;
private:
    IPacketPort& lower_; EventLoop& loop_; Fault fault_;
};

struct Fixture {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    Fabric::Port& forward; Fabric::Port& reverse;
    SemanticFaultPort faults;
    PdsHost source_host,target_host;
    Endpoint source,target;
    explicit Fixture(SemanticFaultPort::Fault fault,size_t receive_limit=4096)
        :forward(fabric.add_host(1)),reverse(fabric.add_host(2)),faults(forward,loop,fault),
         source_host(1,loop,trace,faults),target_host(2,loop,trace,reverse),
         source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16,100*kMillisecond,nullptr,8,receive_limit) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source.memory().add_job(1); target.memory().add_job(1);
    }
    void close() {
        source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
    }
};

void rejected_message_cannot_take_later_posting(bool exhaust_records) {
    Fixture test(SemanticFaultPort::Fault::DelayTail,exhaust_records?1:4096);
    const auto region=test.target.memory().register_region(1,1,64,7);
    size_t reads=0; bool readable=true;
    Operation send; send.type=OperationType::Send; send.peer=2; send.delivery_mode=RUD;
    send.payload_source=std::make_shared<GeneratedPayload>(1024*1024,[&](uint64_t,uint8_t* bytes,size_t count) {
        CHECK(readable); ++reads; std::memset(bytes,0x77,count);
    });
    test.source.submit(send); test.loop.run_until(kMillisecond);
    Completion completion{};
    const bool got_error=test.source.poll_completion(completion);
    CHECK(got_error && completion.status==CompletionStatus::RemoteError && completion.remote_code==5);
    const auto reads_at_completion=reads; readable=false;
    CHECK(test.source.leased_message_ids()==1 && test.target.retained_receive_messages()==1);
    test.target.post_receive(1,1,region.key,0,64,123);
    send.payload_source.reset(); send.payload={1,2,3};
    test.source.submit(send);
    test.loop.run_until(6*kMillisecond);
    CHECK(test.source.poll_completion(completion));
    if (exhaust_records) {
        CHECK(completion.status==CompletionStatus::RemoteError && completion.remote_code==0x1f);
        CHECK(!test.target.poll_completion(completion));
        CHECK(test.target.memory().read(1,1,region.key,0,64)==std::vector<uint8_t>(64,0));
    } else {
        CHECK(completion.status==CompletionStatus::Success);
        CHECK(test.target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==123);
        CHECK(test.target.memory().read(1,1,region.key,0,3)==std::vector<uint8_t>({1,2,3}));
        CHECK(test.target.memory().read(1,1,region.key,3,61)==std::vector<uint8_t>(61,0));
    }
    test.loop.run(100000);
    CHECK(reads==reads_at_completion && reads<=16 && test.faults.aborts==1);
    CHECK(test.source.queued_fragments()==0 && test.source.leased_message_ids()==0 && test.target.retained_receive_messages()==0);
    if (exhaust_records) {
        // Closing the exhausted PDC releases the conservative refusal policy;
        // the posting remained available throughout both rejected messages.
        CHECK(test.source_host.request_connection_close(test.faults.first_pdc)); test.loop.run(100000);
        test.source.submit(send); test.loop.run(100000);
        CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
        CHECK(test.target.poll_completion(completion) && completion.context==123);
    }
    test.close();
}

void poisoned_rud_message(SemanticFaultPort::Fault fault) {
    Fixture test(fault);
    const auto region=test.target.memory().register_region(1,1,64,7);
    Operation write; write.type=OperationType::Write; write.delivery_mode=RUD; write.peer=2;
    write.remote_key=region.key; write.payload.assign(48,0xaa); write.immediate_data=0x123456789abcdef0ull;
    test.source.submit(write); test.loop.run(100000);
    Completion completion{};
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError && completion.remote_code==0x23);
    CHECK(test.target.poll_completion(completion) && completion.status==CompletionStatus::RemoteError && completion.receive);
    CHECK(completion.remote_code==0x23 && completion.immediate_data==write.immediate_data);
    CHECK(!test.target.poll_completion(completion) && !test.source.poll_completion(completion));
    CHECK(test.target.memory().read(1,1,region.key,0,64)==std::vector<uint8_t>(64,0));
    CHECK(test.source.leased_message_ids()==0 && test.target.retained_receive_messages()==0);
    test.close();
}

void receive_truncation() {
    Fixture test(SemanticFaultPort::Fault::None);
    const auto region=test.target.memory().register_region(1,1,64,7);
    test.target.post_receive(1,1,region.key,0,8,42);
    Operation send; send.type=OperationType::Send; send.peer=2; send.payload.assign(48,0xaa);
    test.source.submit(send); test.loop.run(100000);
    Completion completion{};
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError && completion.remote_code==7);
    CHECK(test.target.poll_completion(completion) && completion.status==CompletionStatus::Truncated && completion.context==42);
    CHECK(completion.length==0 && completion.original_length==48);
    CHECK(!test.target.poll_completion(completion));
    CHECK(test.target.memory().read(1,1,region.key,0,64)==std::vector<uint8_t>(64,0));
    test.target.post_receive(1,1,region.key,0,64,43);
    send.payload={4,5,6}; test.source.submit(send); test.loop.run(100000);
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(test.target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==43);
    test.close();
}

void unavailable_application_bytes(bool fail_at_start) {
    Fixture test(SemanticFaultPort::Fault::None);
    const auto region=test.target.memory().register_region(1,1,1024*1024,7);
    size_t reads=0;
    auto payload=std::make_shared<GeneratedPayload>(1024*1024,[&](uint64_t offset,uint8_t* bytes,size_t count) {
        ++reads;
        if (fail_at_start || offset) throw std::runtime_error("injected application read failure");
        std::memset(bytes,0x55,count);
    });
    std::weak_ptr<const PayloadSource> lifetime=payload;
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=region.key;
    write.immediate_data=789; write.payload_source=std::move(payload);
    test.source.submit(std::move(write));
    Completion completion{};
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::LocalError);
    CHECK(lifetime.expired());
    test.loop.run(100000);
    CHECK(reads==(fail_at_start?1:2) && test.faults.aborts==1);
    CHECK(test.target.poll_completion(completion) && completion.remote_code==0x23 && completion.immediate_data==789);
    const auto prefix=test.target.memory().read(1,1,region.key,0,32);
    for (size_t offset=0;offset<prefix.size();++offset) CHECK(prefix[offset]==(!fail_at_start && offset<16?0x55:0));
    CHECK(test.source.leased_message_ids()==0 && test.target.retained_receive_messages()==0);
    test.close();
}

int main() {
    try {
        rejected_message_cannot_take_later_posting(false);
        rejected_message_cannot_take_later_posting(true);
        poisoned_rud_message(SemanticFaultPort::Fault::InitiatorError);
        poisoned_rud_message(SemanticFaultPort::Fault::EarlyMessageError);
        receive_truncation();
        unavailable_application_bytes(true); unavailable_application_bytes(false);
        std::cout<<"PASS: first-error retention, bounded failure state, no reads after error, IE/early MSG_ERROR, CQ data and truncation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
