#include "Check.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <streambuf>

using namespace UET::Runtime;
using namespace UET::SES;

class QuietDiagnostics : private std::streambuf {
public:
    QuietDiagnostics():previous_(std::cout.rdbuf(this)) {}
    ~QuietDiagnostics() { std::cout.rdbuf(previous_); }
private:
    int overflow(int value) override { return traits_type::not_eof(value); }
    std::streambuf* previous_;
};

// Faults live at the frame boundary. The real UDP tunnel never repairs them.
class LossProbe : public IPacketPort {
public:
    LossProbe(UdpFramePort& port,bool server):port_(port),server_(server) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        const bool request=packet.PDS_type==RUOD_req_header;
        const bool semantic_reply=packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE;
        if (request && packet.PDS_header.RUOD_req_header.flags.retx) ++retransmissions;
        if (!dropped && ((!server_ && request) || (server_ && semantic_reply))) {
            dropped=true; return SendResult::Accepted;
        }
        return port_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { port_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { port_.set_writable_handler(std::move(callback)); }
    bool dropped=false;
    size_t retransmissions=0;
private:
    UdpFramePort& port_;
    bool server_;
};

int main(int argc,char** argv) {
    try {
        CHECK(argc==3);
        const bool server=std::string(argv[1])=="server";
        const bool ipv6_udp=std::string(argv[2])=="ipv6-udp";
        std::string result;
        {
            QuietDiagnostics diagnostics;
            RealtimeRuntime runtime; auto& loop=runtime.events(); Trace trace(loop);
            const uint32_t local_node=server?2:1,remote_node=server?1:2;
            UdpFramePort port(local_node);
            LossProbe lossy(port,server);
            UET::NetworkLayer::WireOptions wire; wire.ipv6=ipv6_udp; wire.udp=ipv6_udp;
            PdsHost host(local_node,loop,trace,lossy,PdsHost::WireFormat::Uet11,wire);
            host.services().rto_ms=20;
            Endpoint endpoint(local_node,host,loop,trace,257,2*1000*kMillisecond);
            endpoint.memory().add_job(1);
            auto buffer=std::make_shared<std::vector<uint8_t>>(8192,0);
            const auto region=endpoint.memory().register_buffer(1,1,buffer->data(),buffer->size(),7,{},buffer);
            endpoint.post_receive(1,1,region.key,server?5000:0,32,77);
            if (server) endpoint.post_receive(1,1,region.key,5100,8,78);
            // Only address/key setup uses stdin/stdout. Every application byte
            // and completion must traverse the two independent protocol stacks.
            std::cerr<<"READY "<<port.local_port()<<' '<<region.key<<std::endl;
            uint16_t peer_port=0; uint64_t peer_key=0;
            CHECK(static_cast<bool>(std::cin>>peer_port>>peer_key));
            port.add_peer(remote_node,"127.0.0.1",peer_port);
            runtime.progress(); // Submission time excludes test setup/stdin wait.
            if (!server) {
                Operation write; write.type=OperationType::Write; write.peer=remote_node;
                write.remote_key=peer_key; write.remote_offset=16; write.immediate_data=123;
                write.payload.resize(4097);
                for (size_t byte=0;byte<write.payload.size();++byte) write.payload[byte]=static_cast<uint8_t>(byte*7);
                endpoint.submit(write);
                Operation increment; increment.type=OperationType::Atomic; increment.peer=remote_node;
                increment.remote_key=peer_key; increment.payload={1,0,0,0,0,0,0,0};
                endpoint.submit(increment);
                Operation send; send.type=OperationType::Send; send.peer=remote_node; send.payload={9,8,7};
                endpoint.submit(send);
                write.remote_key=0; write.payload={99}; write.immediate_data.reset();
                endpoint.submit(write);
            }
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(8);
            size_t successful_operations=0,remote_errors=0,receives=0;
            bool reply_started=false,done_started=false,done_received=false,finished=false;
            while (!finished && std::chrono::steady_clock::now()<deadline) {
                port.progress(); runtime.progress(10000);
                Completion completion{};
                while (endpoint.poll_completion(completion)) {
                    if (completion.receive) {
                        CHECK(completion.status==CompletionStatus::Success);
                        if (server && completion.immediate_data) CHECK(*completion.immediate_data==123);
                        else if (server && completion.context==78) done_received=true;
                        else { CHECK(completion.context==77); ++receives; }
                    } else if (completion.status==CompletionStatus::Success) ++successful_operations;
                    else {
                        if (server || completion.status!=CompletionStatus::RemoteError || completion.remote_code!=0x1c)
                            std::cerr<<"unexpected completion node="<<local_node<<" operation="<<completion.operation
                                <<" status="<<static_cast<int>(completion.status)<<" code="<<unsigned(completion.remote_code)<<'\n';
                        CHECK(!server && completion.status==CompletionStatus::RemoteError && completion.remote_code==0x1c);
                        ++remote_errors;
                    }
                }
                if (server && receives==1 && !reply_started) {
                    CHECK((*buffer)[0]==1 && (*buffer)[5000]==9 && (*buffer)[5002]==7);
                    for (size_t byte=0;byte<4097;++byte) CHECK((*buffer)[16+byte]==static_cast<uint8_t>(byte*7));
                    Operation reply; reply.type=OperationType::Send; reply.peer=remote_node; reply.payload={6,5,4};
                    endpoint.submit(reply); reply_started=true;
                }
                if (!server && successful_operations==3 && remote_errors==1 && receives==1 && !done_started) {
                    Operation done; done.type=OperationType::Send; done.peer=remote_node; done.payload={1};
                    endpoint.submit(done); done_started=true;
                }
                finished=server?(reply_started && successful_operations==1 && done_received):
                    (done_started && successful_operations==4);
                if (!finished) {
                    pollfd readiness{port.descriptor(),POLLIN,0};
                    ::poll(&readiness,1,1); // Application wait, outside protocol progress.
                }
            }
            if (!finished) {
                std::cerr<<"incomplete node="<<local_node<<" ok="<<successful_operations<<" errors="<<remote_errors
                    <<" receives="<<receives<<" reply="<<reply_started<<" retransmits="<<lossy.retransmissions
                    <<" trace="<<trace.events().size()<<" counter="<<unsigned((*buffer)[0])<<'\n';
                const auto start=trace.events().size()>20?trace.events().size()-20:0;
                for (size_t index=start;index<trace.events().size();++index) {
                    const auto& event=trace.events()[index];
                    std::cerr<<event.time<<' '<<event.event<<' '<<event.value<<'\n';
                }
            }
            CHECK(finished && lossy.dropped);
            if (!server) {
                CHECK((*buffer)[0]==6 && (*buffer)[1]==5 && (*buffer)[2]==4);
                CHECK(lossy.retransmissions>0);
            }
            CHECK(port.discarded_datagrams()==0);
            endpoint.close(); host.close(); port.close();
            CHECK(loop.pending()==0);
            result=std::string("PASS ")+(server?"server":"client")+" "+argv[2]+" real processes, checked host MR, WRITE/SEND/atomic/error and PDS recovery";
        }
        std::cout<<result<<'\n';
        return 0;
    } catch (const std::exception& error) { std::cerr<<"FAIL "<<error.what()<<'\n'; return 1; }
}
