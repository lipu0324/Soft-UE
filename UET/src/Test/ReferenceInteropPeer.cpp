#include "Check.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <streambuf>

using namespace UET::Runtime;
using namespace UET::SES;

class QuietReferenceDiagnostics : private std::streambuf {
public:
    QuietReferenceDiagnostics():previous_(std::cout.rdbuf(this)) {}
    ~QuietReferenceDiagnostics() { std::cout.rdbuf(previous_); }
private:
    int overflow(int value) override { return traits_type::not_eof(value); }
    std::streambuf* previous_;
};

int main() {
    try {
        {
            QuietReferenceDiagnostics diagnostics;
            RealtimeRuntime runtime; auto& loop=runtime.events(); Trace trace(loop);
            UdpFramePort port(1);
            PdsHost host(1,loop,trace,port);
            // Real-time CPU scheduling is outside the simulated network model.
            // A generous RTO avoids inferring loss merely from a descheduled peer.
            host.services().rto_ms=20;
            // The reference endpoint's negotiated maximum SES payload is 1024.
            // SOM has no explicit payload-length field, so both endpoints use
            // that same configured bound (§3.4.3.3) for multi-packet messages.
            Endpoint endpoint(1,host,loop,trace,1024,5*1000*kMillisecond);
            endpoint.memory().add_job(1);
            std::vector<uint8_t> receive_buffer(32);
            const auto receive_region=endpoint.memory().register_buffer(1,1,receive_buffer.data(),receive_buffer.size(),7);
            endpoint.post_receive(1,1,receive_region.key,0,receive_buffer.size(),77);
            std::cerr<<"READY "<<port.local_port()<<std::endl;
            uint16_t target_port=0,target_pid=0,target_resource=0; uint64_t target_key=0;
            CHECK(static_cast<bool>(std::cin>>target_port>>target_key>>target_pid>>target_resource));
            port.add_peer(2,"127.0.0.1",target_port);
            runtime.progress(); // Align initial submissions with current real time.
            Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=target_key;
            write.target_pid=target_pid; write.target_resource=target_resource;
            write.payload.resize(2049);
            for (size_t byte=0;byte<write.payload.size();++byte) write.payload[byte]=static_cast<uint8_t>(byte*7);
            endpoint.submit(write);
            Operation increment; increment.type=OperationType::Atomic; increment.peer=2;
            increment.target_pid=target_pid; increment.target_resource=target_resource;
            increment.remote_key=target_key; increment.remote_offset=3072;
            increment.payload={1,0,0,0,0,0,0,0};
            endpoint.submit(increment);
            Operation send; send.type=OperationType::Send; send.peer=2; send.target_pid=target_pid;
            send.target_resource=target_resource; send.payload={'a','b','c'};
            endpoint.submit(send);
            size_t sends=0,receives=0;
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(8);
            while ((sends!=3 || receives!=1 || endpoint.retained_receive_messages()!=0) && std::chrono::steady_clock::now()<deadline) {
                port.progress(); runtime.progress(10000);
                Completion completion{};
                while (endpoint.poll_completion(completion)) {
                    if (completion.status!=CompletionStatus::Success) {
                        std::cerr<<"FAIL Soft-UE completion status="<<static_cast<int>(completion.status)
                            <<" code="<<unsigned(completion.remote_code)<<'\n';
                        return 1;
                    }
                    if (completion.receive) { CHECK(completion.context==77); ++receives; }
                    else ++sends;
                }
                pollfd readiness{port.descriptor(),POLLIN,0}; ::poll(&readiness,1,1);
            }
            if (sends!=3 || receives!=1 || endpoint.retained_receive_messages()!=0) {
                std::cerr<<"FAIL Soft-UE interop timeout sends="<<sends<<" receives="<<receives<<'\n';
                for (const auto& event:trace.events()) std::cerr<<event.time<<' '<<event.event<<' '<<event.value<<'\n';
                return 1;
            }
            CHECK(receive_buffer[0]==6 && receive_buffer[1]==5 && receive_buffer[2]==4);
            endpoint.close(); host.close(); port.close(); CHECK(loop.pending()==0);
        }
        std::cout<<"PASS Soft-UE: WRITE/SEND/AMO completed against the reference stack and reply reached host memory\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
