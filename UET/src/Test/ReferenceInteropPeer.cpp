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
            // The pinned independent peer uses native IP with experimental protocol 253.
            // This is an explicit lab interop setting, not Soft-UE's portable default.
            UET::NetworkLayer::WireOptions network; network.udp=false; network.native_ip_protocol=253;
            PdsHost host(1,loop,trace,port,PdsHost::WireFormat::Uet11,network);
            // Real-time CPU scheduling is outside the simulated network model.
            // A generous RTO avoids inferring loss merely from a descheduled peer.
            host.services().rto_ns=20*UET::Runtime::kMillisecond;
            // The reference endpoint's negotiated maximum SES payload is 1024.
            // SOM has no explicit payload-length field, so both endpoints use
            // that same configured bound (§3.4.3.3) for multi-packet messages.
            Endpoint endpoint(1,host,loop,trace,1024,5*1000*kMillisecond);
            endpoint.memory().add_job(1);
            std::vector<uint8_t> receive_buffer(8192);
            const auto receive_region=endpoint.memory().register_buffer(1,1,receive_buffer.data(),receive_buffer.size(),7);
            endpoint.post_receive(1,1,receive_region.key,0,16,77);
            endpoint.post_tagged_receive(1,1,receive_region.key,48,16,{0x0123456789abcdefULL,0,{}},78);
            std::cerr<<"READY "<<port.local_port()<<' '<<receive_region.key<<" 1 1"<<std::endl;
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
            // Independent pinned SES/PDS serves a standard data ACK. Read
            // bytes just written by the preceding ordered WRITE; placement
            // uses a local MR descriptor, never the remote wire address.
            Operation read; read.type=OperationType::Read; read.peer=2; read.remote_key=target_key;
            read.target_pid=target_pid; read.target_resource=target_resource;
            read.remote_offset=13; read.read_length=16;
            read.read_result=ReadResultBuffer{receive_region.key,16,16,1,1};
            endpoint.submit(read);
            Operation fetch; fetch.type=OperationType::FetchingAtomic; fetch.peer=2; fetch.remote_key=target_key;
            fetch.target_pid=target_pid; fetch.target_resource=target_resource; fetch.remote_offset=3072;
            fetch.payload={1,0,0,0,0,0,0,0};
            fetch.atomic_result=AtomicResultBuffer{receive_region.key,32,8,1,1};
            endpoint.submit(fetch); // Reference returns old1 and atomically stores2.
            Operation compare=fetch; compare.atomic_operation=IntegerAtomicOperation::CompareSwapEqual;
            compare.atomic_compare={2,0,0,0,0,0,0,0}; compare.payload={9,0,0,0,0,0,0,0};
            compare.atomic_result=AtomicResultBuffer{receive_region.key,40,8,1,1};
            endpoint.submit(compare); // Its padded32B request returns old2 and stores9.
            Operation send; send.type=OperationType::Send; send.peer=2; send.target_pid=target_pid;
            send.target_resource=target_resource; send.payload={'a','b','c'};
            endpoint.submit(send);
            Operation tagged=send; tagged.type=OperationType::TaggedSend;
            tagged.tag=0xfedcba9876543210ULL; tagged.payload={7,8,9};
            endpoint.submit(tagged);
            const auto synchronized_group=endpoint.begin_synchronized_group(2,1,3);
            CHECK(synchronized_group);
            Operation synchronized_write=write; synchronized_write.type=OperationType::SynchronizedWrite;
            synchronized_write.synchronization=synchronized_group; synchronized_write.remote_offset=3200;
            synchronized_write.payload.assign(19,0x71); endpoint.submit(synchronized_write);
            synchronized_write.remote_offset=3232; synchronized_write.payload.assign(17,0x82); endpoint.submit(synchronized_write);
            Operation synchronized_atomic=increment; synchronized_atomic.type=OperationType::SynchronizedAtomic;
            synchronized_atomic.synchronization=synchronized_group; synchronized_atomic.remote_offset=3264;
            synchronized_atomic.payload={5,0,0,0,0,0,0,0}; endpoint.submit(synchronized_atomic);
            Operation rudi_write=write; rudi_write.delivery_mode=RUDI;
            rudi_write.remote_offset=4096; rudi_write.payload.assign(1113,0x63);
            const auto rudi_write_id=endpoint.submit(rudi_write);
            bool rudi_read_started=false;
            const auto reverse_synchronization_complete=[&] {
                for (size_t byte=64;byte<83;++byte) if (receive_buffer[byte]!=0xa1) return false;
                for (size_t byte=112;byte<120;++byte) if (receive_buffer[byte]) return false;
                // The pinned source requests CPU-coherent atomics (sem_ctl2).
                // This memory model promises network atomicity only; §3.4.9.2
                // requires RC_AMO_UNSUPPORTED_OP rather than a false success.
                return std::any_of(trace.events().begin(),trace.events().end(),[](const TraceEvent& event) {
                    return event.node==1 && event.event=="synchronized_member_failed" &&
                        event.value==static_cast<uint8_t>(SemanticReturnCode::AtomicUnsupportedOperation);
                });
            };
            bool final_send_started=false;
            size_t sends=0,receives=0;
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(8);
            while ((sends!=14 || receives!=3 || endpoint.retained_receive_messages()!=0 || !reverse_synchronization_complete()) && std::chrono::steady_clock::now()<deadline) {
                port.progress(); runtime.progress(10000);
                Completion completion{};
                while (endpoint.poll_completion(completion)) {
                    if (completion.status!=CompletionStatus::Success) {
                        std::cerr<<"FAIL Soft-UE operation="<<completion.operation<<" completion status="<<static_cast<int>(completion.status)
                            <<" code="<<unsigned(completion.remote_code)<<'\n';
                        for (const auto& event:trace.events()) std::cerr<<event.time<<' '<<event.event<<' '<<event.value<<'\n';
                        return 1;
                    }
                    if (completion.receive) {
                        CHECK((completion.context==77 && !completion.tag) ||
                            (completion.context==78 && completion.tag==0x0123456789abcdefULL) ||
                            (completion.context==0 && completion.length==19 && completion.immediate_data==99));
                        ++receives;
                    }
                    else {
                        ++sends;
                        if (completion.operation==rudi_write_id) {
                            // RUDI does not order independent operations. The
                            // application observes WRITE completion before
                            // reading those bytes through the reference SES.
                            // The pinned reference interprets continuation
                            // payload_length as returned byte count; our
                            // no-payload READ path uses zero (Table3-10).
                            // Keep that recorded divergence explicit. These
                            // are two independent single-request READs, not
                            // evidence for a multi-packet READ to the reference.
                            for (const uint32_t offset:{0u,1024u}) {
                                Operation rudi_read=read; rudi_read.delivery_mode=RUDI;
                                rudi_read.remote_offset=4096+offset; rudi_read.read_length=std::min<uint32_t>(1024,1113-offset);
                                rudi_read.read_result=ReadResultBuffer{receive_region.key,4096+offset,rudi_read.read_length,1,1};
                                endpoint.submit(rudi_read);
                            }
                            rudi_read_started=true;
                        }
                    }
                }
                if (!final_send_started && sends==13 && receives==3 && !endpoint.retained_receive_messages() && reverse_synchronization_complete()) {
                    // The application handshake proves the reference's Clear
                    // retired its reverse synchronized messages at this peer.
                    Operation final=send; final.payload={'d','o','n','e'}; endpoint.submit(final); final_send_started=true;
                }
                pollfd readiness{port.descriptor(),POLLIN,0}; ::poll(&readiness,1,1);
            }
            if (sends!=14 || receives!=3 || endpoint.retained_receive_messages()!=0 || !reverse_synchronization_complete()) {
                std::cerr<<"FAIL Soft-UE interop timeout sends="<<sends<<" receives="<<receives<<'\n';
                for (const auto& event:trace.events()) std::cerr<<event.time<<' '<<event.event<<' '<<event.value<<'\n';
                return 1;
            }
            CHECK(receive_buffer[0]==6 && receive_buffer[1]==5 && receive_buffer[2]==4);
            CHECK(receive_buffer[48]==3 && receive_buffer[49]==2 && receive_buffer[50]==1);
            CHECK(rudi_read_started);
            for (size_t byte=4096;byte<4096+1113;++byte) CHECK(receive_buffer[byte]==0x63);
            for (size_t byte=0;byte<16;++byte) CHECK(receive_buffer[16+byte]==static_cast<uint8_t>((13+byte)*7));
            for (size_t byte=0;byte<8;++byte) {
                CHECK(receive_buffer[32+byte]==(byte?0:1)); CHECK(receive_buffer[40+byte]==(byte?0:2));
            }
            endpoint.close(); host.close(); port.close(); CHECK(loop.pending()==0);
        }
        std::cout<<"PASS Soft-UE: forward multi-packet RUDI WRITE and two independent READs, synchronized SUM/WRITE and CPU-coherent rejection\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
