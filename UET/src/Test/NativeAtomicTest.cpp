#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;

class LostAcknowledgementPort : public IPacketPort {
public:
    explicit LostAcknowledgementPort(IPacketPort& lower) : lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        if (drops_remaining) { --drops_remaining; return SendResult::Accepted; }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    size_t drops_remaining=2;
private:
    IPacketPort& lower_;
};

int main() {
    try {
        // Independent arithmetic boundary checks: signed comparison and
        // modulo arithmetic must avoid C++ signed-overflow undefined behavior.
        CHECK(integer_atomic_result(0x80,0x7f,IntegerAtomicOperation::Minimum,IntegerAtomicDatatype::Int8)==0x80);
        CHECK(integer_atomic_result(0x80,0x7f,IntegerAtomicOperation::Minimum,IntegerAtomicDatatype::Uint8)==0x7f);
        CHECK(integer_atomic_result(UINT64_MAX,1,IntegerAtomicOperation::Sum,IntegerAtomicDatatype::Int64)==0);
        CHECK(integer_atomic_result(0,1,IntegerAtomicOperation::Difference,IntegerAtomicDatatype::Uint16)==65535);
        CHECK(integer_atomic_result(0xaa,0x55,IntegerAtomicOperation::BitwiseXor,IntegerAtomicDatatype::Uint8)==255);

        EventLoop event_loop; Trace trace(event_loop); Fabric fabric(event_loop,trace,42);
        auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        LostAcknowledgementPort lossy_target(target_port);
        PdsHost source_host(1,event_loop,trace,source_port),target_host(2,event_loop,trace,lossy_target);
        Endpoint source(1,source_host,event_loop,trace,17),target(2,target_host,event_loop,trace,17);
        source.memory().add_job(1); target.memory().add_job(1);
        const auto region=target.memory().register_region(1,1,1024,7);
        Operation atomic; atomic.type=OperationType::Atomic; atomic.peer=2;
        atomic.remote_key=region.key; atomic.payload={1,0,0,0,0,0,0,0};
        source.submit(atomic); event_loop.run_until(5*kMillisecond);
        Completion completion{};
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
        CHECK(target.memory().read(1,1,region.key,0,8)==atomic.payload); // Sum executes once despite lost ACKs.
        CHECK(!source.poll_completion(completion));

        for (uint8_t encoding=0;encoding<8;++encoding) {
            atomic.atomic_datatype=static_cast<IntegerAtomicDatatype>(encoding);
            const auto width=integer_atomic_width(atomic.atomic_datatype);
            atomic.remote_offset=64+32*encoding; atomic.payload.assign(width*4,0);
            for (size_t element=0;element<4;++element) atomic.payload[element*width]=element+1;
            source.submit(atomic); event_loop.run_until((10+encoding*5)*kMillisecond);
            CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
            CHECK(target.memory().read(1,1,region.key,atomic.remote_offset,atomic.payload.size())==atomic.payload);
        }

        const auto read_only=target.memory().register_region(1,1,64,1);
        atomic.atomic_datatype=IntegerAtomicDatatype::Uint64; atomic.remote_key=read_only.key;
        atomic.remote_offset=0; atomic.payload.assign(8,1);
        source.submit(atomic); event_loop.run_until(55*kMillisecond);
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError);
        CHECK(completion.remote_code==0x18);
        CHECK(target.memory().read(1,1,read_only.key,0,8)==std::vector<uint8_t>(8,0));

        atomic.payload.resize(3);
        source.submit(atomic);
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::InvalidRequest);

        Operation immediate_write; immediate_write.type=OperationType::Write; immediate_write.peer=2;
        immediate_write.remote_key=region.key; immediate_write.remote_offset=512;
        immediate_write.payload.assign(32,0xa5); immediate_write.immediate_data=0x0123456789abcdefULL;
        source.submit(immediate_write); event_loop.run_until(60*kMillisecond);
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
        CHECK(target.poll_completion(completion) && completion.receive);
        CHECK(completion.immediate_data==immediate_write.immediate_data && completion.length==32);
        CHECK(!target.poll_completion(completion));
        CHECK(target.memory().read(1,1,region.key,512,32)==immediate_write.payload);

        source.close(); target.close(); source_host.close(); target_host.close();
        CHECK(event_loop.pending()==0);
        std::cout<<"PASS: integer atomic types, overflow, exactly-once recovery, permissions and WRITE immediate completion\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
