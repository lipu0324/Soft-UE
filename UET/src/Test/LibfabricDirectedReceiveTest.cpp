#include "LibfabricTestSupport.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <rdma/fi_tagged.h>
#include <array>
#include <chrono>
#include <map>

using namespace UET::Runtime;
using namespace UET::SES;

// Two independently progressed native endpoints expose different Job1 rank
// proxies. The provider must match the source address, rather than whichever
// peer happened to arrive first or whichever buffer was posted first.
struct DirectedPeer {
    RealtimeRuntime runtime;
    Trace trace{runtime.events(),0};
    UdpFramePort network{0};
    PdsHost host{network.node(),runtime.events(),trace,network};
    Endpoint endpoint{network.node(),host,runtime.events(),trace,1024,5000*kMillisecond};
    uint16_t provider_node;
    std::map<uint64_t,Completion> completions;
    explicit DirectedPeer(uint16_t destination):provider_node(destination) {
        endpoint.memory().add_job(1); host.services().rto_ns=20*kMillisecond;
        network.add_peer(destination,"127.0.0.1",destination);
    }
    void send(uint8_t byte,bool tagged,bool datagram,uint64_t context) {
        Operation operation; operation.type=datagram?OperationType::DatagramSend:tagged?OperationType::TaggedSend:OperationType::Send;
        operation.peer=provider_node; operation.tag=UINT64_MAX; operation.payload={byte}; operation.context=context;
        endpoint.submit(operation);
    }
    void progress() {
        network.progress(); runtime.progress(10000);
        Completion completion{}; while (endpoint.poll_completion(completion)) CHECK(completions.emplace(completion.context,completion).second);
    }
    void close() { endpoint.close(); host.close(); network.close(); CHECK(!runtime.events().pending()); }
};

void directed_sources(bool tagged,bool datagram,bool directed) {
    ProviderFixture provider(0,FI_FENCE,datagram,FI_CQ_FORMAT_TAGGED,directed);
    CHECK(bool(provider.info->caps&FI_DIRECTED_RECV)==directed);
    CHECK(bool(provider.info->rx_attr->caps&FI_DIRECTED_RECV)==directed);
    CHECK(!(provider.info->tx_attr->caps&FI_DIRECTED_RECV));
    DirectedPeer first(ntohs(provider.address.sin_port)),second(ntohs(provider.address.sin_port));
    provider.add_peer(first.network.local_port()); const auto second_address=provider.add_peer(second.network.local_port());
    std::array<uint8_t,8> filtered{},wildcard{};
    const auto post=[&](void* buffer,fi_addr_t source,uintptr_t context) {
        return tagged?fi_trecv(provider.endpoint,buffer,8,nullptr,source,UINT64_MAX,0,reinterpret_cast<void*>(context)):
            fi_recv(provider.endpoint,buffer,8,nullptr,source,reinterpret_cast<void*>(context));
    };
    if (directed) CHECK(post(filtered.data(),0x12345678,99)==-FI_EADDRNOTAVAIL);
    CHECK(post(filtered.data(),second_address,1)==0);
    CHECK(post(wildcard.data(),FI_ADDR_UNSPEC,2)==0);
    std::map<uintptr_t,fi_cq_tagged_entry> received;
    const auto progress=[&] {
        fi_cq_tagged_entry entries[8]; const auto count=fi_cq_read(provider.completions,entries,8);
        CHECK(count>=0 || count==-FI_EAGAIN);
        for (ssize_t index=0;index<count;++index) CHECK(received.emplace(reinterpret_cast<uintptr_t>(entries[index].op_context),entries[index]).second);
        first.progress(); second.progress();
    };
    const auto until=[&](const auto& ready) {
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        while (!ready() && std::chrono::steady_clock::now()<deadline) progress();
        CHECK(ready());
    };
    first.send(0x11,tagged,datagram,101);
    until([&] { return received.size()==1 && first.completions.size()==1; });
    const uintptr_t first_match=directed?2:1;
    CHECK(received.count(first_match) && (directed?wildcard[0]:filtered[0])==0x11 && (directed?filtered[0]:wildcard[0])==0);
    second.send(0x22,tagged,datagram,102);
    until([&] { return received.size()==2 && second.completions.size()==1; });
    CHECK((directed?filtered[0]:wildcard[0])==0x22);
    for (const auto& [context,completion]:received) {
        CHECK(completion.flags==((tagged?FI_TAGGED:FI_MSG)|FI_RECV) && completion.len==1 &&
            completion.tag==(tagged?UINT64_MAX:0) && completion.buf==(context==1?filtered.data():wildcard.data()));
    }
    for (const auto* peer:{&first,&second}) {
        const auto& completion=peer->completions.begin()->second;
        CHECK(completion.status==(datagram?CompletionStatus::LocalSuccess:CompletionStatus::Success));
    }
    until([&] { return !first.endpoint.leased_message_ids() && !second.endpoint.leased_message_ids(); });
    first.close(); second.close(); provider.close();
}

void receive_only_capability_hint() {
    auto* hints=fi_allocinfo(); CHECK(hints); hints->fabric_attr->prov_name=::strdup("softue");
    hints->ep_attr->type=FI_EP_RDM; hints->caps=FI_MSG; hints->rx_attr->caps=FI_MSG|FI_DIRECTED_RECV;
    fi_info* result=nullptr; CHECK(fi_getinfo(FI_VERSION(2,0),nullptr,nullptr,0,hints,&result)==0);
    CHECK(result && (result->caps&FI_DIRECTED_RECV) && (result->rx_attr->caps&FI_DIRECTED_RECV) && !(result->tx_attr->caps&FI_DIRECTED_RECV));
    fi_freeinfo(result); fi_freeinfo(hints);
}
int main() {
    try {
        for (const bool directed:{false,true}) {
            directed_sources(false,false,directed); directed_sources(true,false,directed); directed_sources(false,true,directed);
        }
        receive_only_capability_hint();
        std::cout<<"PASS directed SEND/tagged/UUD with two real peers, FIFO, opt-in negotiation, ignored source without capability and invalid AV rejection\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
