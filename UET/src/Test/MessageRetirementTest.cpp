#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <streambuf>

using namespace UET::Runtime;
using namespace UET::SES;

// This regression intentionally crosses the complete 16-bit message-ID space.
// Suppress diagnostic stdout; protocol traces remain collected independently.
class DiscardDiagnostics : private std::streambuf {
public:
    DiscardDiagnostics() : previous_(std::cout.rdbuf(this)) {}
    ~DiscardDiagnostics() { std::cout.rdbuf(previous_); }
private:
    int overflow(int value) override { return traits_type::not_eof(value); }
    std::streambuf* previous_;
};

int main() {
    try {
        {
            DiscardDiagnostics diagnostics;
            EventLoop loop; Trace trace(loop,4000000); Fabric fabric(loop,trace,42);
            auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
            fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
            PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
            Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
            source.memory().add_job(1); target.memory().add_job(1);
            const auto counter=target.memory().register_region(1,1,8,7);
            Operation increment; increment.type=OperationType::Atomic; increment.peer=2;
            increment.remote_key=counter.key; increment.payload={1,0,0,0,0,0,0,0};
            constexpr uint64_t operation_count=66000;
            for (uint64_t operation=1;operation<=operation_count;++operation) {
                CHECK(source.submit(increment)==operation);
                loop.run_until(loop.now()+10000,1000);
                Completion completion{};
                CHECK(source.poll_completion(completion) && completion.operation==operation);
                CHECK(completion.status==CompletionStatus::Success && !source.poll_completion(completion));
                CHECK(target.retained_receive_messages()==0 && source.leased_message_ids()==0);
            }
            const auto bytes=target.memory().read(1,1,counter.key,0,8);
            uint64_t observed_counter=0;
            for (size_t byte=0;byte<8;++byte) observed_counter|=uint64_t{bytes[byte]}<<(8*byte);
            CHECK(observed_counter==operation_count);
            source.close(); target.close(); source_host.close(); target_host.close();
            CHECK(loop.pending()==0);
        }
        std::cout<<"PASS: 66000 exactly-once operations, message-ID wrap and bounded semantic-state retirement\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
