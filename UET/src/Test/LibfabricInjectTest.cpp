#include "LibfabricTestSupport.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <rdma/fi_rma.h>
#include <rdma/fi_atomic.h>
#include <array>
#include <chrono>
#include <functional>
#include <map>
#include <vector>
using namespace UET::Runtime;
using namespace UET::SES;

// The initiator uses only public fi_* calls. The native peer supplies checked
// memory and real SES/PDS recovery; the tunnel adds no delivery guarantees.
struct InjectHarness {
    ProviderFixture provider;
    RealtimeRuntime runtime;
    Trace trace{runtime.events(),0};
    UdpFramePort network{0};
    PdsHost host{network.node(),runtime.events(),trace,network};
    Endpoint target{network.node(),host,runtime.events(),trace,1024,5*1000*kMillisecond};
    std::array<uint8_t,4096> memory{};
    Region region{};
    fi_addr_t peer;
    std::map<uintptr_t,fi_cq_data_entry> successes;
    std::vector<Completion> received;
    size_t errors=0;
    std::function<void()> after_progress;

    explicit InjectHarness(uint64_t flags=0,bool datagram=false):provider(0,flags,datagram) {
        CHECK(provider.info->tx_attr->inject_size==256);
        host.services().rto_ns=20*kMillisecond;
        target.memory().add_job(1);
        region=target.memory().register_buffer(1,1,memory.data(),memory.size(),7);
        peer=provider.add_peer(network.local_port());
        network.add_peer(ntohs(provider.address.sin_port),"127.0.0.1",ntohs(provider.address.sin_port));
    }
    void post(uint64_t offset,uint32_t length,uint64_t context) { target.post_receive(1,1,region.key,offset,length,context); }
    void drain(size_t expected_successes,size_t expected_receives,size_t expected_errors=0) {
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        while ((successes.size()<expected_successes || received.size()<expected_receives || errors<expected_errors) &&
               std::chrono::steady_clock::now()<deadline) {
            fi_cq_data_entry entries[8]; const auto count=fi_cq_read(provider.completions,entries,8);
            if (count==-FI_EAVAIL) {
                fi_cq_err_entry error{}; CHECK(fi_cq_readerr(provider.completions,&error,0)==1);
                CHECK(expected_errors && !error.op_context && !error.buf && error.prov_errno==0x1c && error.err==FI_EACCES);
                ++errors;
            } else {
                CHECK(count>=0 || count==-FI_EAGAIN);
                for (ssize_t index=0;index<count;++index) {
                    const auto context=reinterpret_cast<uintptr_t>(entries[index].op_context);
                    CHECK(context && successes.emplace(context,entries[index]).second);
                }
            }
            network.progress(); runtime.progress(10000);
            Completion completion{};
            while (target.poll_completion(completion)) {
                CHECK(completion.receive && completion.status==CompletionStatus::Success); received.push_back(completion);
            }
            if (after_progress) after_progress();
        }
        CHECK(successes.size()==expected_successes && received.size()==expected_receives && errors==expected_errors);
    }
    void close() { target.close(); host.close(); network.close(); provider.close(); CHECK(runtime.events().pending()==0); }
};

void reliable_injection() {
    InjectHarness harness;
    std::array<uint8_t,257> bytes{};
    for (size_t index=0;index<256;++index) bytes[index]=static_cast<uint8_t>(index*3);
    CHECK(fi_inject(harness.provider.endpoint,bytes.data(),256,harness.peer)==0);
    bytes.fill(0xee); // API return permits reuse, including during a semantic NO_MATCH retry.
    std::array<uint8_t,3> data{{1,2,3}};
    CHECK(fi_injectdata(harness.provider.endpoint,data.data(),data.size(),0x1234,harness.peer)==0); data.fill(0);
    bytes.fill(17);
    CHECK(fi_inject_write(harness.provider.endpoint,bytes.data(),256,harness.peer,512,harness.region.key)==0); bytes.fill(0xee);
    data={{4,5,6}};
    CHECK(fi_inject_writedata(harness.provider.endpoint,data.data(),data.size(),99,harness.peer,768,harness.region.key)==0); data.fill(0);
    std::array<uint64_t,33> operands{}; operands.fill(1);
    CHECK(fi_inject_atomic(harness.provider.endpoint,operands.data(),32,harness.peer,1024,harness.region.key,FI_UINT64,FI_SUM)==0);
    operands.fill(99);
    std::array<uint8_t,3> send_data{{7,8,9}}; iovec send_buffer{send_data.data(),send_data.size()}; fi_msg send{};
    send.msg_iov=&send_buffer; send.iov_count=1; send.addr=harness.peer; send.context=reinterpret_cast<void*>(1);
    CHECK(fi_sendmsg(harness.provider.endpoint,&send,FI_INJECT|FI_FENCE)==0); send_data.fill(0);
    std::array<uint8_t,3> write_data{{10,11,12}}; iovec write_buffer{write_data.data(),write_data.size()};
    fi_rma_iov remote_write{784,3,harness.region.key}; fi_msg_rma write{};
    write.msg_iov=&write_buffer; write.iov_count=1; write.addr=harness.peer; write.rma_iov=&remote_write;
    write.rma_iov_count=1; write.context=reinterpret_cast<void*>(2);
    CHECK(fi_writemsg(harness.provider.endpoint,&write,FI_INJECT)==0); write_data.fill(0);
    std::array<uint64_t,2> atomic_data{{2,3}}; fi_ioc atomic_buffer{atomic_data.data(),2};
    fi_rma_ioc remote_atomic{1280,2,harness.region.key}; fi_msg_atomic atomic{};
    atomic.msg_iov=&atomic_buffer; atomic.iov_count=1; atomic.addr=harness.peer; atomic.rma_iov=&remote_atomic;
    atomic.rma_iov_count=1; atomic.datatype=FI_UINT64; atomic.op=FI_SUM; atomic.context=reinterpret_cast<void*>(3);
    CHECK(fi_atomicmsg(harness.provider.endpoint,&atomic,FI_INJECT)==0); atomic_data.fill(99);
    CHECK(fi_inject(harness.provider.endpoint,nullptr,0,harness.peer)==0);
    CHECK(fi_inject(harness.provider.endpoint,bytes.data(),257,harness.peer)==-FI_EMSGSIZE);
    CHECK(fi_inject_write(harness.provider.endpoint,bytes.data(),257,harness.peer,512,harness.region.key)==-FI_EMSGSIZE);
    CHECK(fi_inject_atomic(harness.provider.endpoint,operands.data(),33,harness.peer,1024,harness.region.key,FI_UINT64,FI_SUM)==-FI_EMSGSIZE);
    CHECK(fi_write(harness.provider.endpoint,"done",4,nullptr,harness.peer,800,harness.region.key,reinterpret_cast<void*>(4))==0);
    bool posted=false;
    harness.after_progress=[&] {
        // The first RUD message has already reached SES without a receive.
        // Posting now forces the provider to retry from its owned copy after
        // the application buffers above have been overwritten.
        if (!posted && harness.target.retained_receive_messages()) {
            harness.post(0,256,77); harness.post(256,3,78); harness.post(272,3,79); harness.post(300,1,80); posted=true;
        }
    };
    harness.drain(4,5); CHECK(posted);
    for (size_t index=0;index<256;++index) {
        CHECK(harness.memory[index]==static_cast<uint8_t>(index*3)); CHECK(harness.memory[512+index]==17);
    }
    const std::array<uint8_t,3> expected_send{{1,2,3}},expected_write{{4,5,6}},expected_message{{7,8,9}},expected_rma{{10,11,12}};
    CHECK(std::equal(expected_send.begin(),expected_send.end(),harness.memory.begin()+256));
    CHECK(std::equal(expected_write.begin(),expected_write.end(),harness.memory.begin()+768));
    CHECK(std::equal(expected_message.begin(),expected_message.end(),harness.memory.begin()+272));
    CHECK(std::equal(expected_rma.begin(),expected_rma.end(),harness.memory.begin()+784));
    for (size_t index=0;index<34;++index) {
        uint64_t result=0; std::memcpy(&result,harness.memory.data()+1024+index*8,8);
        CHECK(result==(index<32?1:index==32?2:3));
    }
    CHECK(!std::memcmp(harness.memory.data()+800,"done",4));
    CHECK(std::count_if(harness.received.begin(),harness.received.end(),[](const auto& completion) {
        return completion.context==78 && completion.immediate_data==0x1234;
    })==1);
    CHECK(std::count_if(harness.received.begin(),harness.received.end(),[](const auto& completion) {
        return completion.context==0 && completion.immediate_data==99;
    })==1);
    CHECK(fi_inject_write(harness.provider.endpoint,"bad",3,harness.peer,0,0)==0);
    CHECK(fi_write(harness.provider.endpoint,"next",4,nullptr,harness.peer,804,harness.region.key,reinterpret_cast<void*>(5))==0);
    harness.drain(5,5,1); CHECK(!std::memcmp(harness.memory.data()+804,"next",4));
    harness.close();
}

void default_flags_and_override() {
    InjectHarness harness(FI_INJECT);
    harness.post(0,256,1); harness.post(256,300,2);
    std::array<uint8_t,257> small{}; small.fill(7);
    CHECK(fi_send(harness.provider.endpoint,small.data(),256,nullptr,harness.peer,reinterpret_cast<void*>(1))==0); small.fill(0);
    CHECK(fi_send(harness.provider.endpoint,small.data(),257,nullptr,harness.peer,nullptr)==-FI_EMSGSIZE);
    std::array<uint8_t,300> ordinary{}; ordinary.fill(8); iovec buffer{ordinary.data(),ordinary.size()}; fi_msg message{};
    message.msg_iov=&buffer; message.iov_count=1; message.addr=harness.peer; message.context=reinterpret_cast<void*>(2);
    CHECK(fi_sendmsg(harness.provider.endpoint,&message,0)==0); // Explicit flags override the INJECT default.
    harness.drain(2,2);
    CHECK(std::all_of(harness.memory.begin(),harness.memory.begin()+256,[](auto value) { return value==7; }));
    CHECK(std::all_of(harness.memory.begin()+256,harness.memory.begin()+556,[](auto value) { return value==8; }));
    harness.close();
}
void datagram_injection() {
    InjectHarness harness(0,true); harness.post(0,256,1); harness.post(256,3,2); harness.post(300,1,3);
    std::array<uint8_t,256> bytes{}; bytes.fill(9);
    CHECK(fi_inject(harness.provider.endpoint,bytes.data(),bytes.size(),harness.peer)==0); bytes.fill(0);
    std::array<uint8_t,3> data{{1,2,3}};
    CHECK(fi_injectdata(harness.provider.endpoint,data.data(),3,77,harness.peer)==0); data.fill(0);
    CHECK(fi_send(harness.provider.endpoint,"x",1,nullptr,harness.peer,reinterpret_cast<void*>(1))==0);
    CHECK(fi_inject_write(harness.provider.endpoint,"x",1,harness.peer,0,harness.region.key)==-FI_EOPNOTSUPP);
    uint64_t operand=1;
    CHECK(fi_inject_atomic(harness.provider.endpoint,&operand,1,harness.peer,0,harness.region.key,FI_UINT64,FI_SUM)==-FI_EOPNOTSUPP);
    harness.drain(1,3);
    CHECK(std::all_of(harness.memory.begin(),harness.memory.begin()+256,[](auto value) { return value==9; }));
    CHECK(harness.memory[256]==1 && harness.memory[257]==2 && harness.memory[258]==3);
    harness.close();
}
void injection_size_hints() {
    ProviderFixture provider(0,0); fi_info* result=nullptr;
    provider.hints->tx_attr->inject_size=257;
    CHECK(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,provider.hints,&result)==-FI_ENODATA && !result);
    provider.hints->tx_attr->inject_size=256;
    CHECK(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,provider.hints,&result)==0);
    CHECK(result->tx_attr->inject_size==256); fi_freeinfo(result);
    provider.info->tx_attr->inject_size=257; fid_ep* invalid=nullptr;
    CHECK(fi_endpoint(provider.domain,provider.info,&invalid,nullptr)==-FI_EINVAL && !invalid);
    provider.close();
}
int main() {
    try {
        reliable_injection(); default_flags_and_override(); datagram_injection(); injection_size_hints();
        std::cout<<"PASS injection ownership, retry copies, CQ suppression/errors, flags, boundaries and DGRAM\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
