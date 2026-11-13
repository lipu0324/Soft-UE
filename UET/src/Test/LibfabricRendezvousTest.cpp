#include "LibfabricTestSupport.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <rdma/fi_tagged.h>
#include <algorithm>
#include <chrono>
#include <map>
#include <set>

using namespace UET::Runtime;
using namespace UET::SES;

class RendezvousProviderPort final : public IPacketPort {
public:
    explicit RendezvousProviderPort(UdpFramePort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override { return lower_.try_send(frame); }
    void set_receiver(Receiver receiver) override {
        lower_.set_receiver([this,receiver=std::move(receiver)](Frame frame) {
            const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
            if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header) {
                const auto& response=packet.SESpkt.bth_header.Semantic_Response_Header;
                const auto& transport=packet.PDS_header.RUOD_ack_header;
                const uint32_t sequence=transport.cack_psn+static_cast<int32_t>(transport.ack_psn_off);
                if (response.return_code==1 && response.list==1 &&
                    seen_overflow_.emplace(transport.dpdcid,sequence).second) ++overflow_acceptances;
            }
            if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
                const auto& header=packet.SESpkt.bth_header.Standard_Header;
                if (header.som && seen_.emplace(packet.PDS_header.RUOD_req_header.spdcid,
                    packet.PDS_header.RUOD_req_header.psn).second) {
                    ++opcodes[header.opcode];
                    if (header.opcode==6 || header.opcode==10) {
                        // Inspect the actual standard bytes too: this does not
                        // infer rendezvous merely from the application's size.
                        constexpr size_t semantic=14+20+8+12;
                        CHECK((frame.bytes.at(semantic)&0x3f)==header.opcode);
                        CHECK(packet.SESpkt.eth_header.Rendezvous_Extension_Header.eager_length==1024);
                        last_rendezvous_source_key=packet.SESpkt.eth_header.Rendezvous_Extension_Header.read_mem_key;
                        CHECK(packet.PDS_header.RUOD_req_header.type==(ordered?ROD_REQ:RUD_REQ));
                    }
                }
            }
            receiver(std::move(frame));
        });
    }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool ordered=false;
    std::map<unsigned,size_t> opcodes;
    size_t overflow_acceptances=0;
    uint64_t last_rendezvous_source_key=0;
private:
    UdpFramePort& lower_;
    std::set<std::pair<uint16_t,uint32_t>> seen_;
    std::set<std::pair<uint16_t,uint32_t>> seen_overflow_;
};

struct RendezvousProviderHarness {
    ProviderFixture provider;
    RealtimeRuntime runtime;
    Trace trace{runtime.events(),0};
    UdpFramePort network{0};
    RendezvousProviderPort observed{network};
    PdsHost host{network.node(),runtime.events(),trace,observed};
    Endpoint native{network.node(),host,runtime.events(),trace,1024,5000*kMillisecond};
    Region region;
    fi_addr_t peer;
    std::map<uintptr_t,fi_cq_tagged_entry> successes;
    std::map<uintptr_t,fi_cq_err_entry> errors;
    std::vector<Completion> native_completions;
    explicit RendezvousProviderHarness(bool ordered):provider(ordered?FI_ORDER_SAS:0,FI_FENCE,false,FI_CQ_FORMAT_TAGGED) {
        observed.ordered=ordered; host.services().rto_ns=20*kMillisecond;
        native.memory().add_job(1); region=native.memory().register_region(1,1,256*1024,7);
        peer=provider.add_peer(network.local_port());
        network.add_peer(ntohs(provider.address.sin_port),"127.0.0.1",ntohs(provider.address.sin_port));
    }
    void progress() {
        fi_cq_tagged_entry entries[16]; const auto count=fi_cq_read(provider.completions,entries,16);
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
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(8);
        while (!ready() && std::chrono::steady_clock::now()<deadline) progress();
        CHECK(ready());
    }
    bool native_complete(uint64_t context) const {
        return std::any_of(native_completions.begin(),native_completions.end(),[&](const Completion& completion) {
            return completion.context==context;
        });
    }
    void close() {
        until([&] { return !native.pending() && !native.leased_message_ids() && !native.retained_receive_messages() &&
            !native.retained_rendezvous_receives() && !native.retained_read_packets() && !native.pending_read_returns(); });
        native.close(); host.close(); provider.close();
    }
};

std::vector<uint8_t> payload(size_t length) {
    std::vector<uint8_t> bytes(length);
    for (size_t index=0;index<length;++index) bytes[index]=static_cast<uint8_t>(index*7+3);
    return bytes;
}

void public_send_forms(bool ordered,bool tagged) {
    RendezvousProviderHarness harness(ordered); uintptr_t context=0;
    for (size_t length:{65535,65536,65537}) for (unsigned form=0;form<4;++form) for (bool late:{false,true}) {
        ++context; const auto input=payload(length); const uint64_t tag=UINT64_MAX-context;
        const auto post=[&] {
            if (tagged) harness.native.post_tagged_receive(1,1,harness.region.key,0,length,{tag,0,{}},1000+context);
            else harness.native.post_receive(1,1,harness.region.key,0,length,1000+context);
        };
        const bool rendezvous=length>=65536;
        if (!late || !rendezvous) post();
        const unsigned opcode=tagged?(rendezvous?10:9):(rendezvous?6:5);
        const auto requests_before=harness.observed.opcodes[opcode];
        void* application_context=reinterpret_cast<void*>(context);
        iovec buffer{const_cast<uint8_t*>(input.data()),length}; ssize_t submitted;
        if (tagged) {
            fi_msg_tagged message{}; message.msg_iov=&buffer; message.iov_count=1; message.addr=harness.peer;
            message.tag=tag; message.context=application_context;
            submitted=form==0?fi_tsend(harness.provider.endpoint,input.data(),length,nullptr,harness.peer,tag,application_context):
                form==1?fi_tsendv(harness.provider.endpoint,&buffer,nullptr,1,harness.peer,tag,application_context):
                form==2?fi_tsendmsg(harness.provider.endpoint,&message,FI_FENCE|FI_DELIVERY_COMPLETE):
                fi_tsenddata(harness.provider.endpoint,input.data(),length,nullptr,0,harness.peer,tag,application_context);
        } else {
            fi_msg message{}; message.msg_iov=&buffer; message.iov_count=1; message.addr=harness.peer; message.context=application_context;
            submitted=form==0?fi_send(harness.provider.endpoint,input.data(),length,nullptr,harness.peer,application_context):
                form==1?fi_sendv(harness.provider.endpoint,&buffer,nullptr,1,harness.peer,application_context):
                form==2?fi_sendmsg(harness.provider.endpoint,&message,FI_FENCE|FI_DELIVERY_COMPLETE):
                fi_senddata(harness.provider.endpoint,input.data(),length,nullptr,0,harness.peer,application_context);
        }
        CHECK(submitted==0);
        if (late && rendezvous) {
            harness.until([&] { return harness.native.retained_rendezvous_receives()==1; });
            CHECK(!harness.successes.count(context)); post();
        }
        harness.until([&] { return harness.successes.count(context) && harness.native_complete(1000+context); });
        const auto& completion=harness.successes.at(context);
        CHECK(completion.flags==(tagged?FI_TAGGED|FI_SEND:FI_MSG|FI_SEND) && completion.buf==input.data() && completion.len==length &&
            completion.tag==(tagged?tag:0));
        CHECK(harness.observed.opcodes[opcode]==requests_before+1 && harness.errors.empty());
        const auto received=std::find_if(harness.native_completions.begin(),harness.native_completions.end(),
            [&](const Completion& native) { return native.context==1000+context; });
        CHECK(received->immediate_data==(form==3?std::optional<uint64_t>{0}:std::nullopt));
        CHECK(harness.native.memory().read(1,1,harness.region.key,0,length)==input);
    }
    harness.close(); CHECK(harness.successes.size()==context && harness.native_completions.size()==context);
    for (const auto& completion:harness.native_completions) CHECK(completion.status==CompletionStatus::Success && completion.receive);
}

void public_receive_forms(bool ordered,bool tagged) {
    RendezvousProviderHarness harness(ordered); uintptr_t context=0;
    const size_t length=65537; const auto input=payload(length);
    harness.native.memory().write(1,1,harness.region.key,0,input);
    for (unsigned form=0;form<3;++form) for (bool late:{false,true}) {
        ++context; std::vector<uint8_t> output(length,0xee); const uint64_t tag=UINT64_MAX-context;
        iovec buffer{output.data(),output.size()}; void* application_context=reinterpret_cast<void*>(context);
        const auto post=[&] {
            ssize_t result;
            if (tagged) {
                fi_msg_tagged message{}; message.msg_iov=&buffer; message.iov_count=1; message.addr=FI_ADDR_UNSPEC;
                message.tag=tag&~uint64_t{0xff}; message.ignore=0xff; message.context=application_context;
                result=form==0?fi_trecv(harness.provider.endpoint,output.data(),length,nullptr,FI_ADDR_UNSPEC,message.tag,0xff,application_context):
                    form==1?fi_trecvv(harness.provider.endpoint,&buffer,nullptr,1,FI_ADDR_UNSPEC,message.tag,0xff,application_context):
                    fi_trecvmsg(harness.provider.endpoint,&message,FI_COMPLETION);
            } else {
                fi_msg message{}; message.msg_iov=&buffer; message.iov_count=1; message.addr=FI_ADDR_UNSPEC; message.context=application_context;
                result=form==0?fi_recv(harness.provider.endpoint,output.data(),length,nullptr,FI_ADDR_UNSPEC,application_context):
                    form==1?fi_recvv(harness.provider.endpoint,&buffer,nullptr,1,FI_ADDR_UNSPEC,application_context):
                    fi_recvmsg(harness.provider.endpoint,&message,FI_COMPLETION);
            }
            CHECK(result==0);
        };
        if (!late) post();
        Operation operation; operation.type=tagged?OperationType::RendezvousTaggedSend:OperationType::RendezvousSend;
        operation.peer=ntohs(harness.provider.address.sin_port); operation.tag=tag; operation.context=1000+context;
        operation.rendezvous_source=RendezvousBuffer{harness.region.key,0,static_cast<uint32_t>(length),1,1,0};
        operation.rendezvous_eager_length=1024; operation.immediate_data=0;
        const auto overflow_before=harness.observed.overflow_acceptances;
        harness.native.submit(operation);
        if (late) {
            const auto reads_before=harness.observed.opcodes[2];
            // Drive initial eager to completion but do not wait for the source
            // user CQ, which correctly needs the receiver's later real READ.
            harness.until([&] { return harness.observed.overflow_acceptances>overflow_before; });
            CHECK(!harness.successes.count(context) && harness.observed.opcodes[2]==reads_before); post();
        }
        harness.until([&] { return harness.successes.count(context) && harness.native_complete(1000+context); });
        const auto& completion=harness.successes.at(context);
        CHECK(completion.flags==((tagged?FI_TAGGED|FI_RECV:FI_MSG|FI_RECV)|FI_REMOTE_CQ_DATA) &&
            completion.buf==output.data() && completion.len==length && !completion.data && completion.tag==(tagged?tag:0));
        CHECK(output==input && harness.errors.empty());
    }
    harness.close(); CHECK(harness.successes.size()==context && harness.native_completions.size()==context);
    for (const auto& completion:harness.native_completions) CHECK(completion.status==CompletionStatus::Success && !completion.receive);
}

void threshold_probe(bool disabled) {
    RendezvousProviderHarness harness(false);
    const size_t length=disabled?65536:1024; const auto input=payload(length);
    harness.native.post_receive(1,1,harness.region.key,0,length,101);
    CHECK(fi_send(harness.provider.endpoint,input.data(),length,nullptr,harness.peer,reinterpret_cast<void*>(1))==0);
    harness.until([&] { return harness.successes.count(1) && harness.native_complete(101); });
    CHECK(harness.observed.opcodes[disabled?5:6]==1 && harness.errors.empty());
    CHECK(harness.native.memory().read(1,1,harness.region.key,0,length)==input);
    harness.close(); CHECK(harness.successes.size()==1 && harness.native_completions.size()==1 &&
        harness.native_completions.front().status==CompletionStatus::Success);
}

void public_truncation(bool tagged) {
    RendezvousProviderHarness harness(false); const size_t length=65536;
    const auto input=payload(length); const uint64_t tag=UINT64_MAX;
    if (tagged) harness.native.post_tagged_receive(1,1,harness.region.key,0,length-1,{tag,0,{}},1001);
    else harness.native.post_receive(1,1,harness.region.key,0,length-1,1001);
    CHECK((tagged?fi_tsend(harness.provider.endpoint,input.data(),length,nullptr,harness.peer,tag,reinterpret_cast<void*>(1)):
        fi_send(harness.provider.endpoint,input.data(),length,nullptr,harness.peer,reinterpret_cast<void*>(1)))==0);
    harness.until([&] { return harness.errors.count(1) && harness.native_complete(1001); });
    CHECK(harness.errors.at(1).err==FI_EIO && harness.errors.at(1).prov_errno==static_cast<int>(SemanticReturnCode::UnsupportedSize));
    CHECK(harness.observed.last_rendezvous_source_key);
    Operation probe; probe.type=OperationType::Read; probe.peer=ntohs(harness.provider.address.sin_port);
    probe.remote_key=harness.observed.last_rendezvous_source_key; probe.context=2001;
    harness.native.submit(probe); harness.until([&] { return harness.native_complete(2001); });
    const auto revoked=std::find_if(harness.native_completions.begin(),harness.native_completions.end(),
        [](const Completion& completion) { return completion.context==2001; });
    CHECK(revoked->status==CompletionStatus::RemoteError && revoked->remote_code==static_cast<uint8_t>(SemanticReturnCode::BadMemoryKey));

    harness.native.memory().write(1,1,harness.region.key,0,input);
    std::vector<uint8_t> output(length-1,0xee);
    CHECK((tagged?fi_trecv(harness.provider.endpoint,output.data(),output.size(),nullptr,FI_ADDR_UNSPEC,tag,0,reinterpret_cast<void*>(2)):
        fi_recv(harness.provider.endpoint,output.data(),output.size(),nullptr,FI_ADDR_UNSPEC,reinterpret_cast<void*>(2)))==0);
    Operation operation; operation.type=tagged?OperationType::RendezvousTaggedSend:OperationType::RendezvousSend;
    operation.peer=ntohs(harness.provider.address.sin_port); operation.tag=tag; operation.context=1002; operation.immediate_data=0;
    operation.rendezvous_source=RendezvousBuffer{harness.region.key,0,static_cast<uint32_t>(length),1,1,0};
    operation.rendezvous_eager_length=1024; harness.native.submit(operation);
    harness.until([&] { return harness.errors.count(2) && harness.native_complete(1002); });
    const auto& error=harness.errors.at(2);
    CHECK(error.err==FI_ETRUNC && !error.len && error.olen==length && error.buf==output.data() && !error.data &&
        error.flags==((tagged?FI_TAGGED|FI_RECV:FI_MSG|FI_RECV)|FI_REMOTE_CQ_DATA) && error.tag==(tagged?tag:0));
    CHECK(output==std::vector<uint8_t>(length-1,0xee));
    harness.close(); CHECK(harness.errors.size()==2 && harness.successes.empty() && harness.native_completions.size()==3);
}

int main(int argc,char** argv) {
    try {
        if (argc==2) {
            const std::string option=argv[1];
            CHECK(option=="--ordinary-only" || option=="--small-threshold");
            threshold_probe(option=="--ordinary-only");
            std::cout<<"PASS configured rendezvous threshold "<<option<<'\n'; return 0;
        }
        CHECK(argc==1);
        for (bool ordered:{false,true}) for (bool tagged:{false,true}) {
            public_send_forms(ordered,tagged); public_receive_forms(ordered,tagged);
        }
        for (bool tagged:{false,true}) public_truncation(tagged);
        std::cout<<"PASS public large SEND/tagged rendezvous threshold, scalar/vector/message forms, late receive and CQ data\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
