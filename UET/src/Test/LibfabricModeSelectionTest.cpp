#include "Check.hpp"
#include "LibfabricTestSupport.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_atomic.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <map>
#include <set>
#include <vector>
using namespace UET::Runtime;
using namespace UET::SES;

class ObservedNativePort final : public IPacketPort {
public:
    explicit ObservedNativePort(UdpFramePort& lower):lower_(lower) {}
    std::map<unsigned,unsigned> request_modes;
    std::vector<unsigned> first_request_opcodes;
    SendResult try_send(const Frame& frame) override { return lower_.try_send(frame); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
    void set_receiver(Receiver receiver) override {
        lower_.set_receiver([this,receiver=std::move(receiver)](Frame frame) {
            // Independent extraction of §3.5.10 type[15:11] and §3.4.3.1
            // opcode[5:0]. This test does not ask the provider's mode helper
            // or its decoder which mode it selected.
            CHECK(frame.bytes.size()>=50 && frame.bytes[14]==0x45 && frame.bytes[23]==253);
            const auto type=frame.bytes[38]>>3;
            if (type==2 || type==3) {
                CHECK(frame.bytes.size()>=94);
                CHECK(frame.bytes[51]&0x20); // The provider explicitly chooses GO for all reliable levels.
                const unsigned opcode=frame.bytes[50]&0x3f;
                const auto previous=request_modes.find(opcode);
                CHECK(previous==request_modes.end() || previous->second==type);
                request_modes[opcode]=type;
                const unsigned local_pdc=(unsigned(frame.bytes[46])<<8)|frame.bytes[47];
                uint32_t sequence=0;
                for (size_t offset=42;offset<46;++offset) sequence=(sequence<<8)|frame.bytes[offset];
                if (seen_requests_.emplace(local_pdc,sequence).second) first_request_opcodes.push_back(opcode);
            }
            receiver(std::move(frame));
        });
    }
private:
    UdpFramePort& lower_;
    std::set<std::pair<unsigned,uint32_t>> seen_requests_;
};


void check_delivery_modes(uint64_t ordering,bool ordered_send,bool ordered_rma,bool late_receive=false,uint64_t completion_level=0) {
    const bool receive_was_late=late_receive;
    ProviderFixture provider(ordering,FI_FENCE|completion_level);
    RealtimeRuntime runtime; Trace trace(runtime.events(),0); UdpFramePort network(0);
    ObservedNativePort observed(network);
    PdsHost host(network.node(),runtime.events(),trace,observed); host.services().rto_ns=20*kMillisecond;
    Endpoint target(network.node(),host,runtime.events(),trace,1024,5*1000*kMillisecond);
    target.memory().add_job(1);
    uint8_t memory[64]{};
    const auto region=target.memory().register_buffer(1,1,memory,sizeof(memory),7);
    if (!late_receive) target.post_receive(1,1,region.key,0,8,77);
    const auto peer=provider.add_peer(network.local_port());
    network.add_peer(ntohs(provider.address.sin_port),"127.0.0.1",ntohs(provider.address.sin_port));
    const uint64_t increment=1;
    iovec send_buffer{const_cast<char*>("hi"),2}; fi_msg send{};
    send.msg_iov=&send_buffer; send.iov_count=1; send.addr=peer; send.context=reinterpret_cast<void*>(1);
    CHECK(fi_sendmsg(provider.endpoint,&send,FI_FENCE|completion_level)==0);
    iovec write_buffer{const_cast<char*>("data"),4}; fi_rma_iov remote_write{8,4,region.key}; fi_msg_rma write{};
    write.msg_iov=&write_buffer; write.iov_count=1; write.addr=peer; write.rma_iov=&remote_write;
    write.rma_iov_count=1; write.context=reinterpret_cast<void*>(2);
    CHECK(fi_writemsg(provider.endpoint,&write,FI_FENCE|(completion_level?completion_level:FI_DELIVERY_COMPLETE))==0);
    fi_ioc atomic_buffer{const_cast<uint64_t*>(&increment),1}; fi_rma_ioc remote_atomic{24,1,region.key}; fi_msg_atomic atomic{};
    atomic.msg_iov=&atomic_buffer; atomic.iov_count=1; atomic.addr=peer; atomic.rma_iov=&remote_atomic;
    atomic.rma_iov_count=1; atomic.datatype=FI_UINT64; atomic.op=FI_SUM; atomic.context=reinterpret_cast<void*>(3);
    CHECK(fi_atomicmsg(provider.endpoint,&atomic,FI_FENCE|FI_COMPLETION|completion_level)==0);
    size_t sends=0,receives=0;
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while ((sends<3 || receives<1) && std::chrono::steady_clock::now()<deadline) {
        sends+=provider.progress(); network.progress(); runtime.progress(10000);
        Completion completion{};
        while (target.poll_completion(completion)) { CHECK(completion.receive && completion.status==CompletionStatus::Success); ++receives; }
        if (late_receive && observed.request_modes.count(5)) {
            // The first RUD SEND was rejected with NO_MATCH. The provider
            // must retain its fence while hiding that intermediate error.
            CHECK(!observed.request_modes.count(1) && !observed.request_modes.count(3));
            CHECK(sends==0); // Even weaker requested levels use the documented later GO point.
            target.post_receive(1,1,region.key,0,8,77); late_receive=false;
        }
    }
    CHECK(sends==3 && receives==1);
    CHECK(!std::memcmp(memory,"hi",2) && !std::memcmp(memory+8,"data",4) && memory[24]==1);
    CHECK(observed.request_modes.at(5)==(ordered_send?3u:2u));
    CHECK(observed.request_modes.at(1)==(ordered_rma?3u:2u));
    CHECK(observed.request_modes.at(3)==(ordered_rma?3u:2u));
    // A semantic NO_MATCH retry is a new SEND message with a new PSN. It
    // still precedes every fenced RMA/atomic operation on this source FIFO.
    const auto expected=receive_was_late?std::vector<unsigned>({5,5,1,3}):std::vector<unsigned>({5,1,3});
    CHECK(observed.first_request_opcodes==expected);
    target.close(); host.close(); network.close(); provider.close();
    CHECK(runtime.events().pending()==0);
}

void check_any_job_memory_registration() {
    ProviderFixture provider(0);
    RealtimeRuntime runtime; Trace trace(runtime.events(),0); UdpFramePort network(0);
    PdsHost host(network.node(),runtime.events(),trace,network); host.services().rto_ns=20*kMillisecond;
    Endpoint source(network.node(),host,runtime.events(),trace,1024,5*1000*kMillisecond);
    const auto peer=ntohs(provider.address.sin_port);
    provider.add_peer(network.local_port()); network.add_peer(peer,"127.0.0.1",peer);
    uint8_t memory[3][16]{}; fid_mr* regions[3]{};
    CHECK(fi_mr_reg(provider.domain,memory[0],16,FI_REMOTE_WRITE,0,0,0,&regions[0],nullptr)==0);
    iovec vector{memory[1],16};
    CHECK(fi_mr_regv(provider.domain,&vector,1,FI_REMOTE_WRITE,0,0,0,&regions[1],nullptr)==0);
    vector={memory[2],16}; fi_mr_attr attributes{};
    attributes.mr_iov=&vector; attributes.iov_count=1; attributes.access=FI_REMOTE_WRITE; attributes.iface=FI_HMEM_SYSTEM;
    CHECK(fi_mr_regattr(provider.domain,&attributes,0,&regions[2])==0);
    const auto write=[&](uint32_t job,uint64_t key,CompletionStatus expected,uint8_t code=0) {
        source.memory().add_job(job);
        Operation operation; operation.type=OperationType::Write; operation.job=job;
        operation.peer=peer; operation.relative_addressing=false; operation.remote_key=key;
        operation.remote_offset=4; operation.payload={7,8,9};
        const auto id=source.submit(operation);
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        Completion completion{}; bool completed=false;
        while (!completed && std::chrono::steady_clock::now()<deadline) {
            provider.progress(); network.progress(); runtime.progress(10000);
            completed=source.poll_completion(completion);
        }
        CHECK(completed && completion.operation==id && completion.status==expected && completion.remote_code==code);
    };
    // §2.2.4.3.3: these three public registration APIs authorize any JobID.
    // Absolute addressing makes buffer authorization independent of a relative
    // Job/PID mapping. Even JobID=0 is a valid wire identity, not a wildcard.
    const uint32_t jobs[]={0,2,0xffffff};
    for (size_t index=0;index<3;++index) {
        write(jobs[index],fi_mr_key(regions[index]),CompletionStatus::Success,1);
        const uint8_t expected[]={7,8,9};
        CHECK(!std::memcmp(memory[index]+4,expected,sizeof(expected)));
    }
    const auto revoked_key=fi_mr_key(regions[0]); CHECK(fi_close(&regions[0]->fid)==0); regions[0]=nullptr;
    write(2,revoked_key,CompletionStatus::RemoteError,0x1c);
    uint8_t protected_buffer[16]{}; fid_mr* protected_region=nullptr;
    CHECK(fi_mr_reg(provider.domain,protected_buffer,16,FI_WRITE,0,0,0,&protected_region,nullptr)==0);
    write(2,fi_mr_key(protected_region),CompletionStatus::RemoteError,0x18);
    CHECK(std::all_of(std::begin(protected_buffer),std::end(protected_buffer),[](auto byte) { return byte==0; }));
    CHECK(fi_close(&protected_region->fid)==0);
    for (auto* region:regions) if (region) CHECK(fi_close(&region->fid)==0);
    source.close(); host.close(); network.close(); provider.close(); CHECK(runtime.events().pending()==0);
}
void check_ordering_validation() {
    ProviderFixture provider(0);
    fi_info* rejected=nullptr;
    provider.hints->tx_attr->msg_order=uint64_t{1}<<63;
    CHECK(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,provider.hints,&rejected)==-FI_ENODATA && !rejected);
    provider.hints->tx_attr->msg_order=0; provider.hints->ep_attr->type=FI_EP_DGRAM;
    provider.hints->caps=FI_MSG; provider.hints->rx_attr->msg_order=FI_ORDER_SAS;
    CHECK(fi_getinfo(FI_VERSION(2,0),"127.0.0.1","0",FI_SOURCE,provider.hints,&rejected)==-FI_ENODATA && !rejected);
    provider.info->tx_attr->msg_order=uint64_t{1}<<63; fid_ep* invalid_endpoint=nullptr;
    CHECK(fi_endpoint(provider.domain,provider.info,&invalid_endpoint,nullptr)==-FI_EINVAL && !invalid_endpoint);
    provider.close();
}
int main() {
    try {
        check_delivery_modes(0,false,false);
        check_delivery_modes(0,false,false,true);
        check_delivery_modes(0,false,false,true,FI_INJECT_COMPLETE);
        check_delivery_modes(0,false,false,true,FI_TRANSMIT_COMPLETE);
        check_delivery_modes(FI_ORDER_SAS,true,false,false,FI_DELIVERY_COMPLETE);
        check_delivery_modes(FI_ORDER_SAS,true,false);
        check_delivery_modes(FI_ORDER_RMA_WAW,false,true);
        check_delivery_modes(FI_ORDER_SAS|FI_ORDER_RMA_WAW,true,true);
        for (const auto cross_order:{FI_ORDER_RAS,FI_ORDER_SAR,FI_ORDER_SAW,FI_ORDER_WAS}) check_delivery_modes(cross_order,true,true);
        check_any_job_memory_registration();
        check_ordering_validation();
        std::cout<<"PASS public provider ordering matrix, observed request modes and any-JobID MR authorization\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
