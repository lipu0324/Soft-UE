#include "LibfabricTestSupport.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <rdma/fi_rma.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <string>
#include <vector>

using namespace UET::Runtime;
using namespace UET::SES;

// The public fi_* initiator talks to a native SES/PDS peer. Only this test
// adapter drops a result; the UDP tunnel supplies no reliability of its own.
class ReadLossPort final : public IPacketPort {
public:
    explicit ReadLossPort(UdpFramePort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        const bool result=(packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header) ||
            (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header);
        if (result) {
            ++result_attempts;
            if (lose_first_result && !dropped) { dropped=true; return SendResult::Accepted; }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override {
        lower_.set_receiver([this,receiver=std::move(receiver)](Frame frame) {
            // Independent extraction: Ethernet/IPv4/UDP, 12-byte PDS request,
            // then SES opcode. Observe the actual RUD/ROD choice, not a helper.
            constexpr size_t pds_offset=14+20+8,semantic_offset=pds_offset+12;
            CHECK(frame.bytes.size()>=semantic_offset);
            const unsigned type=frame.bytes[pds_offset]>>3;
            if (type==2 || type==3) {
                CHECK(frame.bytes.size()>=semantic_offset+44);
                const unsigned opcode=frame.bytes[semantic_offset]&0x3f;
                if (opcode==2) {
                    CHECK(type==expected_request_type); ++read_attempts;
                }
            }
            receiver(std::move(frame));
        });
    }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool lose_first_result=false,dropped=false;
    unsigned expected_request_type=2;
    size_t read_attempts=0,result_attempts=0;
private:
    UdpFramePort& lower_;
};

struct ReadHarness {
    ProviderFixture provider;
    RealtimeRuntime runtime;
    Trace trace{runtime.events(),0};
    UdpFramePort network{0};
    ReadLossPort observed{network};
    PdsHost host{network.node(),runtime.events(),trace,observed};
    Endpoint target{network.node(),host,runtime.events(),trace,1024,5000*kMillisecond};
    std::array<uint8_t,65536> memory{};
    Region region;
    fi_addr_t peer;
    std::map<uintptr_t,fi_cq_data_entry> successes;
    std::map<uintptr_t,fi_cq_err_entry> errors;
    std::string scenario;

    explicit ReadHarness(bool ordered=false,uint64_t flags=FI_FENCE):
        provider(ordered?FI_ORDER_RMA_RAW|FI_ORDER_RMA_WAR|FI_ORDER_RMA_WAW:0,flags) {
        host.services().rto_ns=20*kMillisecond;
        target.memory().add_job(1);
        region=target.memory().register_buffer(1,1,memory.data(),memory.size(),Access::Read|Access::Write);
        peer=provider.add_peer(network.local_port());
        network.add_peer(ntohs(provider.address.sin_port),"127.0.0.1",ntohs(provider.address.sin_port));
        observed.expected_request_type=ordered?3:2;
        CHECK((provider.info->caps&(FI_READ|FI_REMOTE_READ))==(FI_READ|FI_REMOTE_READ));
        CHECK((provider.info->tx_attr->caps&FI_READ) && !(provider.info->tx_attr->caps&FI_REMOTE_READ));
        CHECK((provider.info->rx_attr->caps&FI_REMOTE_READ) && !(provider.info->rx_attr->caps&FI_READ));
        CHECK(provider.info->ep_attr->max_order_raw_size==UINT32_MAX && provider.info->ep_attr->max_order_war_size==UINT32_MAX);
    }
    void drain(size_t success_count,size_t error_count=0) {
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        while ((successes.size()<success_count || errors.size()<error_count) && std::chrono::steady_clock::now()<deadline) {
            fi_cq_data_entry entries[8]; const auto count=fi_cq_read(provider.completions,entries,8);
            if (count==-FI_EAVAIL) {
                fi_cq_err_entry error{}; CHECK(fi_cq_readerr(provider.completions,&error,0)==1);
                CHECK(errors.emplace(reinterpret_cast<uintptr_t>(error.op_context),error).second);
            } else {
                CHECK(count>=0 || count==-FI_EAGAIN);
                for (ssize_t index=0;index<count;++index)
                    CHECK(successes.emplace(reinterpret_cast<uintptr_t>(entries[index].op_context),entries[index]).second);
            }
            network.progress(); runtime.progress(10000);
        }
        if (successes.size()!=success_count || errors.size()!=error_count) {
            std::cerr<<"READ drain failed "<<scenario<<" successes="<<successes.size()<<'/'<<success_count
                <<" errors="<<errors.size()<<'/'<<error_count<<" read_requests="<<observed.read_attempts
                <<" result_attempts="<<observed.result_attempts<<" dropped="<<observed.dropped
                <<" target_messages="<<target.retained_receive_messages()<<" target_read_packets="<<target.retained_read_packets()
                <<" target_returns="<<target.pending_read_returns()<<" discarded_udp="<<network.discarded_datagrams()<<'\n';
            for (const auto& [context,completion]:successes)
                std::cerr<<"success context="<<context<<" flags="<<completion.flags<<" bytes="<<completion.len<<'\n';
            for (const auto& [context,error]:errors)
                std::cerr<<"error context="<<context<<" err="<<error.err<<" protocol="<<error.prov_errno<<" bytes="<<error.len<<'\n';
        }
        CHECK(successes.size()==success_count && errors.size()==error_count);
    }
    void close() {
        target.close(); host.close(); network.close(); provider.close(); CHECK(runtime.events().pending()==0);
    }
};

void ordered_read_chain(bool ordered,uint32_t length,bool lose_result) {
    ReadHarness harness(ordered); harness.observed.lose_first_result=lose_result;
    harness.scenario="ordered="+std::to_string(ordered)+" length="+std::to_string(length)+" lose_result="+std::to_string(lose_result);
    std::vector<uint8_t> initial(length),replacement(length,0x5a),first(length,0xee),second(length,0xee);
    for (size_t index=0;index<initial.size();++index) initial[index]=static_cast<uint8_t>(index*17+3);
    const auto context=[](uintptr_t value) { return reinterpret_cast<void*>(value); };
    // RAW, WAR and a second RAW are exercised without waiting between API
    // calls. Lost READ results must be recovered before the later WRITE starts
    // (§3.4.2.7.1.2); otherwise re-executing READ would return replacement data.
    CHECK(fi_write(harness.provider.endpoint,initial.data(),length,nullptr,harness.peer,7,harness.region.key,context(1))==0);
    CHECK(fi_read(harness.provider.endpoint,first.data(),length,nullptr,harness.peer,7,harness.region.key,context(2))==0);
    CHECK(fi_write(harness.provider.endpoint,replacement.data(),length,nullptr,harness.peer,7,harness.region.key,context(3))==0);
    iovec local{second.data(),length}; fi_rma_iov remote{7,length,harness.region.key}; fi_msg_rma message{};
    message.msg_iov=&local; message.iov_count=1; message.rma_iov=&remote; message.rma_iov_count=1;
    message.addr=harness.peer; message.context=context(4);
    CHECK(fi_readmsg(harness.provider.endpoint,&message,FI_FENCE|FI_COMPLETION)==0);
    harness.drain(4);
    CHECK(first==initial && second==replacement && harness.observed.dropped==lose_result);
    for (uintptr_t token:{uintptr_t{2},uintptr_t{4}}) {
        const auto& completion=harness.successes.at(token);
        CHECK(completion.flags==(FI_RMA|FI_READ) && completion.len==length &&
            completion.buf==(token==2?first.data():second.data()));
    }
    CHECK(harness.observed.read_attempts>=2*((uint64_t{length}+1023)/1024));
    harness.close();
}

void validation_and_errors() {
    ReadHarness harness;
    harness.scenario="validation_and_errors";
    std::array<uint8_t,32> result; result.fill(0xee);
    CHECK(fi_read(harness.provider.endpoint,nullptr,1,nullptr,harness.peer,0,harness.region.key,nullptr)==-FI_EMSGSIZE);
    CHECK(fi_read(harness.provider.endpoint,result.data(),uint64_t{UINT32_MAX}+1,nullptr,harness.peer,0,harness.region.key,nullptr)==-FI_EMSGSIZE);
    CHECK(fi_read(harness.provider.endpoint,result.data(),1,nullptr,FI_ADDR_UNSPEC,0,harness.region.key,nullptr)==-FI_EADDRNOTAVAIL);
    iovec local{result.data(),17}; fi_rma_iov remote{0,17,harness.region.key}; fi_msg_rma message{};
    message.msg_iov=&local; message.iov_count=1; message.rma_iov=&remote; message.rma_iov_count=1; message.addr=harness.peer;
    CHECK(fi_readv(harness.provider.endpoint,&local,nullptr,2,harness.peer,0,harness.region.key,nullptr)==-FI_EINVAL);
    CHECK(fi_readmsg(harness.provider.endpoint,&message,FI_INJECT)==-FI_EOPNOTSUPP);
    CHECK(fi_readmsg(harness.provider.endpoint,&message,FI_REMOTE_CQ_DATA)==-FI_EOPNOTSUPP);
    remote.len=16; CHECK(fi_readmsg(harness.provider.endpoint,&message,0)==-FI_EINVAL); remote.len=17;
    const auto denied=harness.target.memory().register_region(1,1,32,static_cast<uint8_t>(Access::Write));
    CHECK(fi_read(harness.provider.endpoint,result.data(),17,nullptr,harness.peer,0,denied.key,reinterpret_cast<void*>(1))==0);
    CHECK(fi_read(harness.provider.endpoint,result.data(),17,nullptr,harness.peer,0,0,reinterpret_cast<void*>(2))==0);
    CHECK(fi_read(harness.provider.endpoint,result.data(),17,nullptr,harness.peer,65530,harness.region.key,reinterpret_cast<void*>(3))==0);
    harness.drain(0,3);
    CHECK(harness.errors.at(1).err==FI_EACCES && harness.errors.at(1).prov_errno==0x18);
    CHECK(harness.errors.at(2).err==FI_EACCES && harness.errors.at(2).prov_errno==0x1c);
    CHECK(harness.errors.at(3).err==FI_EIO && harness.errors.at(3).prov_errno==0x1d);
    for (const auto& [token,error]:harness.errors)
        CHECK(error.flags==(FI_RMA|FI_READ) && error.buf==result.data() && error.len==0);
    CHECK(std::all_of(result.begin(),result.end(),[](auto byte) { return byte==0xee; }));
    harness.memory[0]=0x42;
    CHECK(fi_readv(harness.provider.endpoint,&local,nullptr,1,harness.peer,0,harness.region.key,reinterpret_cast<void*>(4))==0);
    CHECK(fi_read(harness.provider.endpoint,nullptr,0,nullptr,harness.peer,0,harness.region.key,reinterpret_cast<void*>(5))==0);
    harness.drain(2,3); CHECK(result[0]==0x42 && result[17]==0xee && harness.successes.at(5).len==0);
    harness.close();
}

int main() {
    try {
        for (const bool ordered:{false,true}) {
            for (const uint32_t length:{1u,15u,16u,17u,1024u,1025u,32771u}) ordered_read_chain(ordered,length,false);
            ordered_read_chain(ordered,16,true); ordered_read_chain(ordered,32771,true);
        }
        validation_and_errors();
        ProviderFixture datagram(0,0,true); std::array<uint8_t,1> result{};
        CHECK(!(datagram.info->caps&(FI_READ|FI_REMOTE_READ)));
        CHECK(fi_read(datagram.endpoint,result.data(),1,nullptr,FI_ADDR_UNSPEC,0,0,nullptr)==-FI_EOPNOTSUPP); datagram.close();
        ReadHarness injecting(false,FI_INJECT);
        CHECK(fi_read(injecting.provider.endpoint,result.data(),1,nullptr,injecting.peer,0,injecting.region.key,nullptr)==-FI_EOPNOTSUPP);
        injecting.close();
        std::cout<<"PASS public READ APIs, registered placement, RAW/WAR ordering, loss recovery and errors\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
