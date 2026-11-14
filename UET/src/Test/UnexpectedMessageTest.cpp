#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

class EndDelayPort : public IPacketPort {
public:
    EndDelayPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_ack_header) local_context=packet.PDS_header.RUOD_ack_header.spdcid;
        if (drop_end && packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_header.Standard_Header.eom)
            return SendResult::Accepted;
        if (delay_end && packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_header.Standard_Header.eom && loop_.now()<5*kMillisecond) {
            loop_.at(5*kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool delay_end=false,drop_end=false;
    uint16_t local_context=UINT16_MAX;
private:
    IPacketPort& lower_; EventLoop& loop_;
};

struct Fixture {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    Fabric::Port& forward; Fabric::Port& reverse; EndDelayPort source_port,target_port;
    PdsHost source_host,target_host; Endpoint source,target;
    explicit Fixture(size_t budget=64):forward(fabric.add_host(1)),reverse(fabric.add_host(2)),source_port(forward,loop),target_port(reverse,loop),
        source_host(1,loop,trace,source_port),target_host(2,loop,trace,target_port),source(1,source_host,loop,trace,16),
        target(2,target_host,loop,trace,16,100*kMillisecond,nullptr,8,4096,budget) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source.memory().add_job(1); target.memory().add_job(1);
    }
    void close() {
        source.close(); target.close(); source_host.close(); target_host.close();
        loop.run(10000); // Already in-flight fabric frames may outlive the detached host callbacks.
        CHECK(loop.pending()==0);
    }
};

void late_posting(bool partial) {
    Fixture test; test.source_port.delay_end=partial;
    const auto region=test.target.memory().register_region(1,1,128,7);
    Operation send; send.type=OperationType::Send; send.peer=2; send.payload.assign(48,0x55);
    const auto operation=test.source.submit(send); test.loop.run_until(kMillisecond);
    Completion completion{};
    CHECK(!test.source.poll_completion(completion) && !test.target.poll_completion(completion));
    CHECK(test.source.transport_pending(operation) && test.target.unexpected_bytes()==48);
    CHECK(test.target.memory().read(1,1,region.key,0,48)==std::vector<uint8_t>(48,0));
    test.target.post_receive(1,1,region.key,0,64,42);
    if (partial) {
        CHECK(!test.target.poll_completion(completion));
        CHECK(test.target.memory().read(1,1,region.key,0,32)==std::vector<uint8_t>(32,0x55));
    }
    test.loop.run(100000);
    CHECK(test.target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==42 && completion.length==48);
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(test.target.memory().read(1,1,region.key,0,48)==send.payload);
    CHECK(test.target.unexpected_bytes()==0 && test.target.retained_receive_messages()==0 && !test.source.transport_pending(operation));
    test.close();
}

void ordered_buffered_messages_and_truncation() {
    Fixture test;
    const auto region=test.target.memory().register_region(1,1,128,7);
    Operation send; send.type=OperationType::Send; send.peer=2; send.payload.assign(16,1);
    test.source.submit(send); send.payload.assign(16,2); test.source.submit(send);
    test.loop.run_until(kMillisecond); CHECK(test.target.unexpected_bytes()==32);
    test.target.post_receive(1,1,region.key,0,16,1);
    test.target.post_receive(1,1,region.key,16,16,2); test.loop.run(100000);
    Completion completion{};
    CHECK(test.target.poll_completion(completion) && completion.context==1);
    CHECK(test.target.poll_completion(completion) && completion.context==2);
    CHECK(test.target.memory().read(1,1,region.key,0,16)==std::vector<uint8_t>(16,1));
    CHECK(test.target.memory().read(1,1,region.key,16,16)==std::vector<uint8_t>(16,2));
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    send.payload.assign(48,0xaa); test.source.submit(send); test.loop.run_until(test.loop.now()+kMillisecond);
    CHECK(test.target.unexpected_bytes()==48);
    test.target.post_receive(1,1,region.key,64,8,3); test.loop.run(100000);
    CHECK(test.target.poll_completion(completion) && completion.status==CompletionStatus::Truncated && completion.original_length==48 && completion.length==0);
    CHECK(test.source.poll_completion(completion) && completion.remote_code==7);
    CHECK(test.target.memory().read(1,1,region.key,64,64)==std::vector<uint8_t>(64,0));
    CHECK(test.target.unexpected_bytes()==0 && test.target.retained_receive_messages()==0);
    test.close();
}

void exhaustion_generation_and_manual_retry() {
    Fixture test(32);
    const auto region=test.target.memory().register_region(1,1,128,7);
    Operation first; first.type=OperationType::Send; first.peer=2; first.payload.assign(32,1);
    const auto buffered=test.source.submit(first); test.loop.run_until(kMillisecond); CHECK(test.target.unexpected_bytes()==32);
    Operation second=first; second.payload.assign(48,2);
    const auto rejected=test.source.submit(second); test.loop.run_until(2*kMillisecond);
    Completion completion{};
    // §3.5.21.1: the later message's error is ready, but its first ACK
    // cannot pass the earlier SEND's delivery-complete EOM response.
    CHECK(!test.source.poll_completion(completion));
    CHECK(test.source.transport_pending(rejected));
    CHECK(test.target.unexpected_bytes()==32);
    test.target.post_receive(1,1,region.key,0,32,1); test.loop.run_until(3*kMillisecond);
    CHECK(!test.source.transport_pending(rejected));
    CHECK(test.source.poll_completion(completion) && completion.operation==buffered && completion.status==CompletionStatus::Success);
    CHECK(test.source.poll_completion(completion) && completion.operation==rejected && completion.remote_code==4 && completion.remote_generation==0);
    CHECK(test.target.poll_completion(completion) && completion.context==1);
    test.source.submit(second); test.loop.run_until(4*kMillisecond);
    CHECK(test.source.poll_completion(completion) && completion.remote_code==2 && completion.remote_generation==1);
    CHECK(test.target.unexpected_bytes()==0);
    test.target.post_receive(1,1,region.key,32,48,2);
    second.target_generation=1; test.source.submit(second); test.loop.run(100000);
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(test.target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==2);
    CHECK(test.target.memory().read(1,1,region.key,0,32)==first.payload);
    CHECK(test.target.memory().read(1,1,region.key,32,48)==second.payload);
    // Generation changes in the SEND index space do not change RMA selection.
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=region.key; write.remote_offset=100; write.payload={9};
    test.source.submit(write); test.loop.run(100000);
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(test.target.memory().read(1,1,region.key,100,1)[0]==9);
    CHECK(test.target.unexpected_bytes()==0 && test.target.retained_receive_messages()==0);
    test.close();
}

void rud_no_match_and_close_cleanup() {
    Fixture test;
    const auto region=test.target.memory().register_region(1,1,64,7);
    Operation send; send.type=OperationType::Send; send.peer=2; send.delivery_mode=RUD; send.payload={1,2,3};
    const auto rejected=test.source.submit(send); test.loop.run(100000);
    Completion completion{};
    CHECK(test.source.poll_completion(completion) && completion.remote_code==5 && completion.length==0);
    CHECK(!test.source.transport_pending(rejected) && test.target.unexpected_bytes()==0);
    test.target.post_receive(1,1,region.key,0,64,42); test.source.submit(send); test.loop.run(100000);
    CHECK(test.source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(test.target.poll_completion(completion) && completion.context==42);
    send.delivery_mode=ROD; test.source.submit(send); test.loop.run_until(test.loop.now()+kMillisecond);
    CHECK(test.target.unexpected_bytes()==3);
    test.close(); CHECK(test.target.unexpected_bytes()==0);
}

void failed_context_completes_partial_receive() {
    Fixture test; test.source_port.drop_end=true;
    const auto region=test.target.memory().register_region(1,1,64,7);
    test.target.post_receive(1,1,region.key,0,64,100);
    Operation send; send.type=OperationType::Send; send.peer=2; send.payload.assign(48,0x5a);
    test.source.submit(send); test.loop.run_until(kMillisecond/2);
    CHECK(test.target.memory().read(1,1,region.key,0,32)==std::vector<uint8_t>(32,0x5a));
    test.source.close(); test.source_host.close(); // No peer can answer the target's Close Request.
    CHECK(test.target_port.local_context!=UINT16_MAX && test.target_host.request_connection_close(test.target_port.local_context));
    test.loop.run(100000);
    Completion completion{};
    CHECK(test.target.poll_completion(completion) && completion.receive && completion.context==100);
    CHECK(completion.status==CompletionStatus::Timeout && completion.length==32 && completion.original_length==48);
    CHECK(!test.target.poll_completion(completion) && test.target.retained_receive_messages()==0);
    CHECK(test.target.memory().read(1,1,region.key,32,32)==std::vector<uint8_t>(32,0));
    test.close();
}

int main() {
    try {
        late_posting(false); late_posting(true); ordered_buffered_messages_and_truncation();
        exhaustion_generation_and_manual_retry(); rud_no_match_and_close_cleanup();
        failed_context_completes_partial_receive();
        std::cout<<"PASS: bounded ordered unexpected messages, partial/late placement, truncation, generation recovery and RUD retry\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
