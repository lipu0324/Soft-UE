#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// Delay READ confirmations after bytes have actually reached the peer. The
// eager final ACK may then win the race while still honoring delivery-complete
// visibility. Holding packet-level ACK/Clear never fabricates an SES outcome.
class ReadConfirmationGate final : public IPacketPort {
public:
    ReadConfirmationGate(IPacketPort& lower,EventLoop& loop,bool delay):lower_(lower),loop_(loop),delay_(delay) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        const bool data_ack=packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.dpdcid>=MAX_PDC;
        const bool clear=packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Clear_cmd &&
            packet.PDS_header.RUOD_cp_header.dpdcid>=MAX_PDC;
        if (delay_ && loop_.now()<5*kMillisecond && (data_ack || clear)) {
            loop_.at(5*kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; EventLoop& loop_; bool delay_;
};

// An independent SES policy uses the real production PDS to accept/truncate
// eager data and issue ordinary READs. It supplies no reliability or dedup.
// Native target integration and failure matrices live in separate tests.
void source_completion(bool tagged,pdc_mode mode,bool standalone,bool read_first,bool capture,uint32_t total,uint32_t eager) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    ReadConfirmationGate confirmations(reverse,loop,!read_first);
    PdsHost source_host(1,loop,trace,forward),oracle(2,loop,trace,confirmations);
    // Table3-35's Max_ACK_DATA_SIZE is fabric-wide, not independently
    // negotiated per peer. Both PDS instances must choose the same carrier.
    source_host.configure_read_ack_data(standalone?0:16); oracle.configure_read_ack_data(standalone?0:16);
    oracle.configure_semantic_payload_mtu(16);
    Endpoint source(1,source_host,loop,trace,16); source.memory().add_job(1);
    auto storage=std::make_shared<SparseMemory>(total+8);
    std::vector<uint8_t> original(total);
    for (uint32_t byte=0;byte<total;++byte) original[byte]=static_cast<uint8_t>(byte*7+3);
    storage->write(4,original.data(),original.size());
    RegionOptions options; options.requested_key=0x1234;
    const auto region=source.memory().register_storage(1,1,storage,1,options);
    SES_Rendezvous_Extension_Header extension{};
    bool read_submitted=false,eager_end=false;
    uint64_t advertised_key=0;
    const uint32_t read_start=capture?0:eager==total?total:eager/2;
    const uint32_t read_length=total-read_start;
    std::vector<uint8_t> read_bytes(read_length),eager_bytes(capture?0:eager);
    ReadCoverage read_coverage,eager_coverage;
    bool read_data_seen=false,end_reply_scheduled=false;
    std::optional<PDC_SES_req> pending_end;
    std::function<void()> maybe_finish_eager;
    const auto accept_read_data=[&](const SEStoPDS_pkt& packet) {
        const auto& header=packet.bth_header.Semantic_Response_with_Data_Header;
        CHECK(header.opcode==2 && header.return_code==1 && header.read_request_msg_id==100 &&
            header.modified_length==read_length && header.payload_length==packet.payload.size());
        const auto offset=static_cast<uint32_t>(header.message_offset);
        CHECK(offset<=read_length && packet.payload.size()<=read_length-offset);
        const auto added=read_coverage.add(offset,packet.payload.size(),read_length);
        CHECK(added!=ReadCoverage::Addition::Invalid);
        if (added==ReadCoverage::Addition::Added && !packet.payload.empty())
            std::copy(packet.payload.begin(),packet.payload.end(),read_bytes.begin()+offset);
        read_data_seen=true;
        if (maybe_finish_eager) maybe_finish_eager();
    };
    const auto submit_read=[&] {
        CHECK(!read_submitted); read_submitted=true;
        for (uint32_t offset=0;;offset+=16) {
            SES_PDS_req request{}; request.src_fep=2; request.dst_fep=1; request.source_pid=1;
            request.mode=RUD; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
            request.tx_pkt_handle=100; request.pkt.bth_type=Standard_Header; request.pkt_len=44;
            auto& header=request.pkt.bth_header.Standard_Header;
            header.opcode=2; header.rel=1; header.dc=1; header.som=offset==0;
            header.eom=uint64_t{offset}+16>=read_length; header.msg_id=100; header.job_id=1;
            header.PIDonFEP=extension.read_PIDonFEP; header.resource_index=extension.read_resource_index;
            header.ri_generation=extension.read_ri_generation; header.match_bits=extension.read_mem_key;
            header.buffer_offset=extension.read_offset+read_start; header.request_length=read_length; header.initiator=2;
            if (!header.som) { header.diff.som_false.message_offset=offset; header.diff.som_false.payload_length=0; }
            CHECK(oracle.submit(request)); if (header.eom) break;
        }
    };
    const auto reply_eager=[&](const PDC_SES_req& request) {
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.rsp_len=12; response.gtd_del=capture || request.pkt.bth_header.Standard_Header.eom;
        response.rsp.bth_type=Semantic_Response_Header;
        auto& semantic=response.rsp.bth_header.Semantic_Response_Header;
        semantic.opcode=capture?1:0; semantic.list=capture?1:0; semantic.return_code=1;
        semantic.job_id=1; semantic.message_id=request.pkt.bth_header.Standard_Header.msg_id;
        semantic.modified_length=capture?0:total;
        CHECK(oracle.manager().pushSESResponse(response)); oracle.wake();
    };
    maybe_finish_eager=[&] {
        if (!pending_end || end_reply_scheduled || !read_data_seen || read_coverage.bytes()!=read_length ||
            (!capture && eager_coverage.bytes()!=eager)) return;
        end_reply_scheduled=true;
        const auto end=*pending_end;
        if (read_first) loop.after(2*kMillisecond,[&,end] { reply_eager(end); });
        else reply_eager(end);
    };
    oracle.set_request_handler([&](const PDC_SES_req& request) {
        if (request.pkt.bth_type==Semantic_Response_with_Data_Header) {
            accept_read_data(request.pkt);
            SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
            response.rsp_len=12; response.rsp=UET::PDS::default_semantic_response(request.pkt);
            CHECK(oracle.manager().pushSESResponse(response)); oracle.wake(); return;
        }
        const auto& header=request.pkt.bth_header.Standard_Header;
        CHECK(header.opcode==(tagged?10:6) && header.request_length==total && header.initiator==0 && header.hd);
        CHECK(header.match_bits==(tagged?UINT64_MAX:0) && (!header.som || header.diff.som_true.header_data==42));
        extension=request.pkt.eth_header.Rendezvous_Extension_Header;
        CHECK(extension.eager_length==eager && !extension.read_offset && extension.read_mem_key!=region.key);
        advertised_key=extension.read_mem_key;
        const auto offset=header.som?0:header.diff.som_false.message_offset;
        CHECK(offset<=eager && request.pkt.payload.size()<=eager-offset);
        if (!capture) {
            CHECK(eager_coverage.add(offset,request.pkt.payload.size(),eager)!=ReadCoverage::Addition::Invalid);
            if (!request.pkt.payload.empty()) std::copy(request.pkt.payload.begin(),request.pkt.payload.end(),eager_bytes.begin()+offset);
        }
        if (header.eom) {
            CHECK(!eager_end); eager_end=true;
            pending_end=request;
        } else reply_eager(request);
        if (!read_submitted) submit_read();
        maybe_finish_eager();
    });
    oracle.set_response_handler([&](const PDC_SES_rsp& response) {
        if (response.pkt.bth_type==Semantic_Response_with_Data_Header) accept_read_data(response.pkt);
        else CHECK(response.pkt.bth_type==Semantic_Response_Header && response.pkt.bth_header.Semantic_Response_Header.return_code==1);
    });
    Operation operation; operation.type=tagged?OperationType::RendezvousTaggedSend:OperationType::RendezvousSend;
    operation.peer=2; operation.delivery_mode=mode; operation.initiator_id=0; operation.tag=UINT64_MAX;
    operation.rendezvous_source=RendezvousBuffer{region.key,4,total,1,1,0}; operation.rendezvous_eager_length=eager;
    operation.context=99; operation.immediate_data=42;
    const auto submitted=source.submit(operation);
    loop.run_until(kMillisecond);
    Completion completion{};
    CHECK(source.pending()==1 && source.transport_pending(submitted) && !source.poll_completion(completion));
    loop.run(100000);
    if (!source.poll_completion(completion)) throw std::runtime_error("missing rendezvous source completion");
    if (completion.status!=CompletionStatus::Success)
        std::cerr<<"status="<<unsigned(completion.status)<<" code="<<unsigned(completion.remote_code)<<" total="<<total
            <<" eager="<<eager<<" capture="<<capture<<" standalone="<<standalone<<" read_first="<<read_first<<'\n';
    CHECK(completion.operation==submitted && completion.context==99 && completion.status==CompletionStatus::Success &&
        completion.length==total && !source.poll_completion(completion));
    CHECK(read_submitted && read_data_seen && eager_end && read_coverage.bytes()==read_length);
    CHECK(read_bytes==std::vector<uint8_t>(original.begin()+read_start,original.end()));
    if (!capture) CHECK(eager_bytes==std::vector<uint8_t>(original.begin(),original.begin()+eager));
    Time eager_completed=0,read_confirmed=0;
    for (const auto& event:trace.events()) if (event.node==1 && event.value==submitted) {
        if (event.event=="rendezvous_eager_complete") eager_completed=event.time;
        if (event.event=="rendezvous_read_confirmed") read_confirmed=event.time;
    }
    CHECK(eager_completed && read_confirmed && (read_first?read_confirmed<eager_completed:eager_completed<read_confirmed));
    check_throws<MemoryAccessError>([&] { source.memory().read(1,1,advertised_key,0,0); });
    if (source.pending() || source.transport_pending(submitted) || source.leased_message_ids() || source.retained_receive_messages() ||
        source.retained_read_packets() || source.pending_read_returns())
        std::cerr<<"resources="<<source.pending()<<'/'<<source.transport_pending(submitted)<<'/'<<source.leased_message_ids()
            <<'/'<<source.retained_receive_messages()<<'/'<<source.retained_read_packets()<<'/'<<source.pending_read_returns()
            <<" total="<<total<<" eager="<<eager<<" tagged="<<tagged<<" mode="<<mode<<" standalone="<<standalone
            <<" read_first="<<read_first<<" capture="<<capture<<'\n';
    CHECK(!source.pending() && !source.transport_pending(submitted) && !source.leased_message_ids() &&
        !source.retained_receive_messages() && !source.retained_read_packets() && !source.pending_read_returns());
    source.close(); source_host.close(); oracle.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (bool tagged:{false,true}) for (auto mode:{RUD,ROD}) for (bool standalone:{false,true})
            for (bool read_first:{false,true}) for (bool capture:{false,true}) for (uint32_t total:{0,1,16,17,73}) {
                const std::set<uint32_t> eager_lengths={0,std::min<uint32_t>(1,total),std::min<uint32_t>(16,total),total};
                for (const auto eager:eager_lengths) source_completion(tagged,mode,standalone,read_first,capture,total,eager);
            }
        std::cout<<"PASS rendezvous source eager/READ completion ordering, truncation, overlap, aliases, zero/MTU/multifragment and both READ carriers\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
