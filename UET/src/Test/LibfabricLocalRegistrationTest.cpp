#include "LibfabricTestSupport.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <algorithm>
#include <array>
#include <chrono>

using namespace UET::Runtime;
using namespace UET::SES;

int main() {
    try {
        ProviderFixture provider(0);
        std::array<uint8_t,8> public_buffer{};
        std::array<uint8_t,32> receive_buffer{};
        fid_mr* public_region=nullptr;
        CHECK(fi_mr_reg(provider.domain,public_buffer.data(),public_buffer.size(),FI_REMOTE_WRITE,0,0,0,&public_region,nullptr)==0);
        CHECK(fi_recv(provider.endpoint,receive_buffer.data(),receive_buffer.size(),nullptr,FI_ADDR_UNSPEC,reinterpret_cast<void*>(77))==0);
        // The pinned simulator allocator increments its vendor key. Deliberately
        // address the otherwise hidden receive registration: opacity alone
        // must not turn its local Write permission into remote RMA authority.
        const auto receive_key=fi_mr_key(public_region)+1;
        RealtimeRuntime runtime; Trace trace(runtime.events()); UdpFramePort network(0);
        PdsHost host(network.node(),runtime.events(),trace,network); host.services().rto_ns=20*kMillisecond;
        Endpoint source(network.node(),host,runtime.events(),trace,1024,5000*kMillisecond);
        source.memory().add_job(1);
        const auto peer=ntohs(provider.address.sin_port);
        network.add_peer(peer,"127.0.0.1",peer); provider.add_peer(network.local_port());
        size_t receives=0;
        const auto execute=[&](Operation operation,CompletionStatus status,uint8_t code,bool posted_delivery) {
            runtime.progress(); operation.peer=peer; operation.delivery_mode=ROD;
            const auto submitted=source.submit(std::move(operation));
            bool completed=false; const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
            while ((!completed || (posted_delivery && !receives)) && std::chrono::steady_clock::now()<deadline) {
                fi_cq_data_entry entry{}; const auto count=fi_cq_read(provider.completions,&entry,1);
                if (count==1) {
                    CHECK(posted_delivery && !receives && entry.op_context==reinterpret_cast<void*>(77) &&
                        entry.buf==receive_buffer.data() && entry.len==3 && entry.flags==(FI_MSG|FI_RECV));
                    ++receives;
                } else CHECK(count==-FI_EAGAIN);
                network.progress(); runtime.progress(10000);
                Completion completion{};
                while (source.poll_completion(completion)) {
                    if (completion.status!=status || completion.remote_code!=code)
                        std::cerr<<"unexpected direct-access result status="<<static_cast<int>(completion.status)
                            <<" code="<<unsigned(completion.remote_code)<<" receive_buffer[0]="<<unsigned(receive_buffer[0])<<'\n';
                    CHECK(!completed && completion.operation==submitted && completion.status==status && completion.remote_code==code);
                    completed=true;
                }
            }
            CHECK(completed && receives==(posted_delivery?1:0));
        };
        Operation direct_write; direct_write.type=OperationType::Write; direct_write.remote_key=receive_key; direct_write.payload={99};
        execute(direct_write,CompletionStatus::RemoteError,0x18,false);
        CHECK(std::all_of(receive_buffer.begin(),receive_buffer.end(),[](auto byte) { return byte==0; }));
        Operation send; send.type=OperationType::Send; send.payload={'s','e','s'};
        execute(send,CompletionStatus::Success,1,true);
        CHECK(receive_buffer[0]=='s' && receive_buffer[1]=='e' && receive_buffer[2]=='s' && receive_buffer[3]==0);
        source.close(); host.close(); network.close(); CHECK(runtime.events().pending()==0);
        CHECK(fi_close(&public_region->fid)==0); provider.close();
        std::cout<<"PASS implicit provider receive MR rejects known-key direct RMA and accepts posted SEND placement\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
