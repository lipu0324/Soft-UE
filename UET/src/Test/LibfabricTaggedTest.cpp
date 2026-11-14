#include "LibfabricTestSupport.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <set>
#include <vector>

using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

class TaggedProviderPort final : public IPacketPort {
public:
    explicit TaggedProviderPort(UdpFramePort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header) {
            const auto& result=packet.SESpkt.bth_header.Semantic_Response_Header;
            const auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
            // ACK_PSN is CACK plus its signed offset (§3.5.11.4.4),
            // modulo2^32. Cache replays are one semantic failure, not retries.
            const uint32_t original_sequence=acknowledgment.cack_psn+static_cast<int32_t>(acknowledgment.ack_psn_off);
            if (seen_results.emplace(acknowledgment.dpdcid,original_sequence,result.return_code).second) {
                if (result.return_code==2) ++bad_generations;
                if (result.return_code==5) ++no_matches;
            }
            if (drop_success && result.return_code==1) { drop_success=false; dropped=true; return SendResult::Accepted; }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override {
        lower_.set_receiver([this,receiver=std::move(receiver)](Frame frame) {
            // Extract the actual PDS type/opcode/generation from fixed standard
            // bytes; this assertion does not reuse the provider's mode helper.
            constexpr size_t pds=14+20+8,semantic=pds+12;
            CHECK(frame.bytes.size()>=semantic);
            const auto type=frame.bytes[pds]>>3;
            if (type==2 || type==3) {
                const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
                if (packet.SESpkt.bth_type==Standard_Header) {
                    const auto& header=packet.SESpkt.bth_header.Standard_Header;
                    const auto& request=packet.PDS_header.RUOD_req_header;
                    if (seen_requests.emplace(request.spdcid,request.psn).second) {
                        generations[header.opcode].push_back(header.ri_generation);
                        if (header.opcode==9) CHECK(type==expected_tagged_type && (frame.bytes[semantic]&0x3f)==9);
                    }
                }
            }
            receiver(std::move(frame));
        });
    }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    unsigned expected_tagged_type=2;
    bool drop_success=false,dropped=false;
    size_t bad_generations=0,no_matches=0;
    std::map<unsigned,std::vector<uint8_t>> generations;
private:
    UdpFramePort& lower_;
    std::set<std::pair<uint16_t,uint32_t>> seen_requests;
    std::set<std::tuple<uint16_t,uint32_t,uint8_t>> seen_results;
};

struct TaggedProviderHarness {
    ProviderFixture provider;
    RealtimeRuntime runtime;
    Trace trace{runtime.events(),0};
    UdpFramePort network{0};
    TaggedProviderPort observed{network};
    PdsHost host{network.node(),runtime.events(),trace,observed};
    Endpoint native{network.node(),host,runtime.events(),trace,1024,5000*kMillisecond};
    Region remote;
    fi_addr_t peer;
    std::map<uintptr_t,fi_cq_tagged_entry> successes;
    std::map<uintptr_t,fi_cq_err_entry> errors;
    std::vector<Completion> native_completions;
    explicit TaggedProviderHarness(bool ordered=false):provider(ordered?FI_ORDER_SAS:0,FI_FENCE,false,FI_CQ_FORMAT_TAGGED) {
        CHECK((provider.info->caps&FI_TAGGED) && provider.info->ep_attr->mem_tag_format==UINT64_MAX);
        CHECK(!(provider.info->caps&FI_DIRECTED_RECV));
        host.services().rto_ns=20*kMillisecond;
        native.memory().add_job(1); remote=native.memory().register_region(1,1,65536,7);
        peer=provider.add_peer(network.local_port());
        network.add_peer(ntohs(provider.address.sin_port),"127.0.0.1",ntohs(provider.address.sin_port));
        observed.expected_tagged_type=ordered?3:2;
    }
    void progress() {
        fi_cq_tagged_entry entries[8]; const auto count=fi_cq_read(provider.completions,entries,8);
        if (count==-FI_EAVAIL) {
            fi_cq_err_entry error{}; CHECK(fi_cq_readerr(provider.completions,&error,0)==1);
            CHECK(errors.emplace(reinterpret_cast<uintptr_t>(error.op_context),error).second);
        } else {
            CHECK(count>=0 || count==-FI_EAGAIN);
            for (ssize_t index=0;index<count;++index)
                CHECK(successes.emplace(reinterpret_cast<uintptr_t>(entries[index].op_context),entries[index]).second);
        }
        network.progress(); runtime.progress(10000);
        Completion completion{}; while (native.poll_completion(completion)) native_completions.push_back(completion);
    }
    template<class Predicate> void until(Predicate ready) {
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        while (!ready() && std::chrono::steady_clock::now()<deadline) progress();
        CHECK(ready());
    }
    void complete(uintptr_t context,uint64_t flags,void* buffer,size_t length,uint64_t tag) {
        until([&] { return successes.count(context); });
        const auto& completion=successes.at(context);
        CHECK(completion.flags==flags && completion.buf==buffer && completion.len==length && completion.tag==tag);
    }
    Operation tagged(uint64_t tag,std::vector<uint8_t> bytes,uint64_t context) const {
        Operation operation; operation.type=OperationType::TaggedSend; operation.peer=ntohs(provider.address.sin_port);
        operation.tag=tag; operation.payload=std::move(bytes); operation.context=context;
        return operation;
    }
    void close() {
        until([&] { return !native.pending() && !native.leased_message_ids() && !native.retained_receive_messages(); });
        native.close(); host.close(); provider.close();
    }
};

void public_forms(bool ordered) {
    TaggedProviderHarness harness(ordered);
    uintptr_t context=1;
    for (const size_t length:{0,1,17,1024,1025,32771}) for (unsigned form=0;form<3;++form) {
        std::vector<uint8_t> input(length); for (size_t byte=0;byte<length;++byte) input[byte]=static_cast<uint8_t>(byte*7+form);
        const uint64_t tag=UINT64_MAX-form;
        harness.native.post_tagged_receive(1,1,harness.remote.key,0,length,{tag,0,{}},100+context);
        auto* application_context=reinterpret_cast<void*>(context);
        iovec vector{input.data(),input.size()}; fi_msg_tagged message{};
        message.msg_iov=&vector; message.iov_count=1; message.addr=harness.peer; message.tag=tag; message.context=application_context;
        const auto submitted=form==0?fi_tsend(harness.provider.endpoint,input.data(),length,nullptr,harness.peer,tag,application_context):
            form==1?fi_tsendv(harness.provider.endpoint,&vector,nullptr,1,harness.peer,tag,application_context):
            fi_tsendmsg(harness.provider.endpoint,&message,FI_FENCE|FI_DELIVERY_COMPLETE);
        CHECK(submitted==0);
        harness.complete(context,FI_TAGGED|FI_SEND,input.data(),length,tag);
        // Reverse SEND completion may arrive in the same progress call as
        // this receive. Select by application identity, never by poll order.
        const auto matching_receive=[&](const Completion& completion) { return completion.receive && completion.context==100+context; };
        harness.until([&] { return std::any_of(harness.native_completions.begin(),harness.native_completions.end(),matching_receive); });
        const auto& received=*std::find_if(harness.native_completions.begin(),harness.native_completions.end(),matching_receive);
        CHECK(received.receive && received.status==CompletionStatus::Success && received.context==100+context && received.tag==tag && received.length==length);
        CHECK(harness.native.memory().read(1,1,harness.remote.key,0,length)==input);
        ++context;
        // Reverse direction: v/msg wildcard matching must return all actual
        // tag bits. The automatic result registration is private local state.
        std::vector<uint8_t> output(length,0xee); vector={output.data(),output.size()};
        message.msg_iov=&vector; message.addr=FI_ADDR_UNSPEC; message.tag=tag&~uint64_t{0xff};
        message.ignore=0xff; message.context=reinterpret_cast<void*>(context);
        const auto received_post=form==0?fi_trecv(harness.provider.endpoint,output.data(),length,nullptr,FI_ADDR_UNSPEC,message.tag,0xff,message.context):
            form==1?fi_trecvv(harness.provider.endpoint,&vector,nullptr,1,FI_ADDR_UNSPEC,message.tag,0xff,message.context):
            fi_trecvmsg(harness.provider.endpoint,&message,FI_COMPLETION);
        CHECK(received_post==0);
        auto operation=harness.tagged(tag,input,1000+context); if (form==2) operation.immediate_data=0;
        harness.native.submit(operation);
        harness.complete(context,FI_TAGGED|FI_RECV|(form==2?FI_REMOTE_CQ_DATA:0),output.data(),length,tag);
        CHECK(output==input && harness.successes.at(context).data==0); ++context;
    }
    CHECK(harness.errors.empty()); harness.close();
}

void mixed_fifo_and_inject(bool ordered) {
    TaggedProviderHarness harness(ordered);
    std::array<uint8_t,8> wildcard{},exact{},plain{};
    CHECK(fi_trecv(harness.provider.endpoint,wildcard.data(),8,nullptr,FI_ADDR_UNSPEC,0,UINT64_MAX,reinterpret_cast<void*>(1))==0);
    CHECK(fi_recv(harness.provider.endpoint,plain.data(),8,nullptr,FI_ADDR_UNSPEC,reinterpret_cast<void*>(3))==0);
    CHECK(fi_trecv(harness.provider.endpoint,exact.data(),8,nullptr,FI_ADDR_UNSPEC,UINT64_MAX,0,reinterpret_cast<void*>(2))==0);
    harness.native.submit(harness.tagged(UINT64_MAX,{1},101));
    harness.native.submit(harness.tagged(UINT64_MAX,{2},102));
    auto ordinary=harness.tagged(0,{3},103); ordinary.type=OperationType::Send; harness.native.submit(ordinary);
    harness.complete(1,FI_TAGGED|FI_RECV,wildcard.data(),1,UINT64_MAX);
    harness.complete(2,FI_TAGGED|FI_RECV,exact.data(),1,UINT64_MAX);
    harness.complete(3,FI_MSG|FI_RECV,plain.data(),1,0);
    CHECK(wildcard[0]==1 && exact[0]==2 && plain[0]==3);
    const auto completions_before=harness.successes.size();
    for (unsigned data=0;data<2;++data) {
        const uint64_t tag=data?UINT64_MAX:0;
        harness.native.post_tagged_receive(1,1,harness.remote.key,16+data*8,8,{tag,0,{}},200+data);
        std::array<uint8_t,3> input{{7,8,9}};
        CHECK((data?fi_tinjectdata(harness.provider.endpoint,input.data(),input.size(),UINT64_MAX,harness.peer,tag):
            fi_tinject(harness.provider.endpoint,input.data(),input.size(),harness.peer,tag))==0);
        input.fill(0xee); // FI_INJECT owns its copy before returning.
        harness.until([&] { return std::any_of(harness.native_completions.begin(),harness.native_completions.end(),
            [&](const Completion& completion) { return completion.context==200+data; }); });
        CHECK(harness.native.memory().read(1,1,harness.remote.key,16+data*8,3)==std::vector<uint8_t>({7,8,9}));
        const auto found=std::find_if(harness.native_completions.begin(),harness.native_completions.end(),
            [&](const Completion& completion) { return completion.context==200+data; });
        CHECK(found->tag==tag && (data?found->immediate_data==UINT64_MAX:!found->immediate_data));
    }
    harness.close(); CHECK(harness.successes.size()==completions_before && harness.errors.empty());
}

void generation_spaces_and_cached_result() {
    TaggedProviderHarness harness;
    harness.native.resources().configure_resource(1,1,ResourceSpace::Tagged,7);
    harness.native.resources().configure_resource(1,1,ResourceSpace::Send,3);
    harness.native.resources().configure_resource(1,1,ResourceSpace::Rma,9);
    harness.native.post_tagged_receive(1,1,harness.remote.key,0,8,{0,UINT64_MAX,{}},101);
    harness.native.post_tagged_receive(1,1,harness.remote.key,8,8,{0,UINT64_MAX,{}},104);
    harness.native.post_receive(1,1,harness.remote.key,16,8,102);
    std::array<uint8_t,3> input{{1,2,3}};
    harness.observed.drop_success=true;
    CHECK(fi_tsend(harness.provider.endpoint,input.data(),3,nullptr,harness.peer,UINT64_MAX,reinterpret_cast<void*>(1))==0);
    CHECK(fi_send(harness.provider.endpoint,input.data(),3,nullptr,harness.peer,reinterpret_cast<void*>(2))==0);
    CHECK(fi_write(harness.provider.endpoint,input.data(),3,nullptr,harness.peer,24,harness.remote.key,reinterpret_cast<void*>(3))==0);
    CHECK(fi_tsenddata(harness.provider.endpoint,input.data(),3,nullptr,UINT64_MAX,harness.peer,0,reinterpret_cast<void*>(4))==0);
    for (uintptr_t context=1;context<=4;++context)
        harness.complete(context,context==2?FI_MSG|FI_SEND:context==3?FI_RMA|FI_WRITE:FI_TAGGED|FI_SEND,input.data(),3,context==1?UINT64_MAX:0);
    harness.until([&] { return harness.native_completions.size()==3; });
    CHECK(harness.observed.dropped && harness.observed.bad_generations==3 && harness.errors.empty());
    CHECK(harness.observed.generations.at(9)==std::vector<uint8_t>({0,7,7}));
    CHECK(harness.observed.generations.at(5)==std::vector<uint8_t>({0,3}));
    CHECK(harness.observed.generations.at(1)==std::vector<uint8_t>({0,9}));
    for (const uint64_t offset:{0,8,16,24}) CHECK(harness.native.memory().read(1,1,harness.remote.key,offset,3)==std::vector<uint8_t>({1,2,3}));
    harness.close();
}

void late_posting(bool ordered) {
    TaggedProviderHarness harness(ordered); std::array<uint8_t,3> input{{4,5,6}};
    CHECK(fi_tsend(harness.provider.endpoint,input.data(),3,nullptr,harness.peer,0x1234,reinterpret_cast<void*>(1))==0);
    harness.until([&] { return harness.observed.generations.count(9); });
    CHECK(harness.successes.empty());
    harness.native.post_tagged_receive(1,1,harness.remote.key,0,8,{0x1200,0xff,{}},101);
    harness.complete(1,FI_TAGGED|FI_SEND,input.data(),3,0x1234);
    harness.until([&] { return harness.native_completions.size()==1; });
    CHECK(harness.observed.no_matches==(ordered?0:1) && harness.errors.empty()); harness.close();
}

void truncation_and_private_receive() {
    TaggedProviderHarness harness;
    std::array<uint8_t,8> destination{};
    CHECK(fi_trecv(harness.provider.endpoint,destination.data(),2,nullptr,FI_ADDR_UNSPEC,0x1230,0xf,reinterpret_cast<void*>(1))==0);
    auto operation=harness.tagged(0x123a,std::vector<uint8_t>(48,0xaa),101); operation.immediate_data=0xbeef;
    harness.native.submit(operation);
    harness.until([&] { return harness.errors.count(1) && !harness.native_completions.empty(); });
    CHECK(harness.native_completions.back().status==CompletionStatus::RemoteError && harness.native_completions.back().remote_code==7);
    const auto& error=harness.errors.at(1);
    CHECK(error.flags==(FI_TAGGED|FI_RECV|FI_REMOTE_CQ_DATA) && error.err==FI_ETRUNC && error.tag==0x123a &&
        error.data==0xbeef && !error.len && error.olen==48 && error.buf==destination.data());
    CHECK(std::all_of(destination.begin(),destination.end(),[](uint8_t byte) { return !byte; }));
    harness.close();
    TaggedProviderHarness authority;
    std::array<uint8_t,8> public_storage{}; fid_mr* public_registration=nullptr;
    CHECK(fi_mr_reg(authority.provider.domain,public_storage.data(),public_storage.size(),FI_REMOTE_WRITE,0,0,0,
        &public_registration,nullptr)==0);
    const auto private_receive_key=fi_mr_key(public_registration)+1;
    CHECK(fi_trecv(authority.provider.endpoint,destination.data(),8,nullptr,FI_ADDR_UNSPEC,0,0,reinterpret_cast<void*>(2))==0);
    // The pinned allocator assigns the next vendor-space key. Use the full
    // API key, including its metadata; guessing only RKEY=1 would test a
    // nonexistent key rather than the private receive's actual authority.
    operation=authority.tagged(0,{9},102); operation.type=OperationType::Write; operation.remote_key=private_receive_key;
    authority.native.submit(operation);
    authority.until([&] { return !authority.native_completions.empty(); });
    CHECK(authority.native_completions.back().status==CompletionStatus::RemoteError && authority.native_completions.back().remote_code==0x18);
    CHECK(destination[0]==0 && authority.successes.empty() && authority.errors.empty());
    authority.native.submit(authority.tagged(0,{7},103));
    authority.complete(2,FI_TAGGED|FI_RECV,destination.data(),1,0); CHECK(destination[0]==7);
    CHECK(fi_close(&public_registration->fid)==0); authority.close();
}

void invalid_requests() {
    TaggedProviderHarness harness; uint8_t byte=1; iovec vector{&byte,1};
    fi_msg_tagged message{}; message.msg_iov=&vector; message.iov_count=1; message.addr=FI_ADDR_UNSPEC;
    CHECK(fi_trecvmsg(harness.provider.endpoint,&message,FI_PEEK)==-FI_EOPNOTSUPP);
    // Without the opt-in capability, libfabric requires src_addr to be ignored.
    CHECK(fi_trecv(harness.provider.endpoint,&byte,1,nullptr,harness.peer,0,0,nullptr)==0);
    CHECK(fi_tsendv(harness.provider.endpoint,&vector,nullptr,2,harness.peer,0,nullptr)==-FI_EINVAL);
    CHECK(fi_tinject(harness.provider.endpoint,&byte,257,harness.peer,0)==-FI_EMSGSIZE);
    message.addr=harness.peer;
    CHECK(fi_tsendmsg(harness.provider.endpoint,&message,FI_PEEK)==-FI_EOPNOTSUPP);
    harness.close();
    auto* hints=fi_allocinfo(); CHECK(hints); hints->fabric_attr->prov_name=::strdup("softue");
    hints->ep_attr->type=FI_EP_DGRAM; hints->caps=FI_TAGGED;
    fi_info* result=nullptr; CHECK(fi_getinfo(FI_VERSION(2,0),nullptr,nullptr,0,hints,&result)==-FI_ENODATA && !result);
    fi_freeinfo(hints);
}

int main() {
    try {
        for (const bool ordered:{false,true}) { public_forms(ordered); mixed_fifo_and_inject(ordered); late_posting(ordered); }
        generation_spaces_and_cached_result(); truncation_and_private_receive(); invalid_requests();
        std::cout<<"PASS public tagged scalar/vector/msg, CQ tags/data/truncation, inject ownership, FIFO/spaces, recovery and local-only registrations\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
