#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <set>
#include <type_traits>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

PDStoNET_pkt request_packet(uint16_t local,uint16_t peer_pdc,uint32_t peer,pdc_mode mode) {
    PDStoNET_pkt packet{}; packet.src_fep=peer; packet.dst_fep=peer==1?2:1;
    packet.PDS_type=RUOD_req_header; auto& header=packet.PDS_header.RUOD_req_header;
    header.type=mode==RUD?RUD_REQ:ROD_REQ; header.next_hdr=UET_HDR_REQUEST_STD;
    header.psn=1000; header.clear_psn_off=-1; header.spdcid=peer_pdc; header.dpdcid=local;
    header.flags.ar=header.flags.retx=1;
    packet.SESpkt.bth_type=Standard_Header;
    auto& semantic=packet.SESpkt.bth_header.Standard_Header;
    semantic.opcode=1; semantic.som=semantic.eom=semantic.dc=semantic.rel=1;
    semantic.job_id=semantic.PIDonFEP=semantic.resource_index=semantic.msg_id=1;
    semantic.request_length=4; packet.SESpkt.payload={1,2,3,4};
    return packet;
}

template<class Receiver> void kernel_admission(pdc_mode mode) {
    EventLoop loop; Services services{loop,loop,[]{}};
    Receiver receiver(&services);
    const bool initiator=std::is_same_v<Receiver,I_PDC>;
    const uint16_t local=initiator?1:MAX_PDC,remote=initiator?MAX_PDC:1;
    CHECK(receiver.initPDC(local)); receiver.state=ESTABLISHED; receiver.mode=mode; receiver.DPDCID=remote;
    receiver.SYN=0; receiver.start_psn=1000; receiver.rx_cur_psn=receiver.cack_psn=receiver.rx_clear_psn=999;
    receiver.src_fep=initiator?1:2; receiver.dst_fep=initiator?2:1;
    bool available=false; size_t checks=0;
    services.semantic_admission=[&](const PDC_SES_req& descriptor) {
        ++checks;
        CHECK(descriptor.PDCID==local && descriptor.orig_pdcid==remote && descriptor.orig_psn==1000);
        CHECK(descriptor.source_fep==receiver.dst_fep && descriptor.connection_start_psn==1000);
        CHECK(descriptor.rx_pkt_handle==UINT16_MAX && descriptor.pkt.payload.empty());
        CHECK(descriptor.pkt.bth_header.Standard_Header.request_length==4);
        return available?SemanticAdmission::ReservedMessage:SemanticAdmission::Rejected;
    };
    auto packet=request_packet(local,remote,receiver.dst_fep,mode); receiver.rxReq(&packet);
    CHECK(checks==1 && receiver.rx_pkt_map.empty() && receiver.rx_req_pkt_q.empty());
    CHECK(receiver.rx_cur_psn==999 && receiver.cack_psn==999 && receiver.tx_ack_buffer.empty());
    CHECK(receiver.tx_pkt_q.size()==1); const auto refused=receiver.tx_pkt_q.front(); receiver.tx_pkt_q.pop();
    CHECK(refused.PDS_type==nack_header && refused.PDS_header.nack_header.nack_code==UET_NO_SES_MSG_AVAIL);
    CHECK(refused.PDS_header.nack_header.spdcid==local && refused.PDS_header.nack_header.flags.retx);
    if (mode==ROD) CHECK(refused.PDS_header.nack_header.payload==1000);
    available=true; receiver.rxReq(&packet);
    CHECK(checks==2 && receiver.rx_pkt_map.size()==1 && receiver.rx_req_pkt_q.size()==1);
    CHECK(receiver.rx_req_pkt_q.front().pkt.payload==packet.SESpkt.payload);
    receiver.rxReq(&packet); packet.PDS_header.RUOD_req_header.flags.retx=0; receiver.rxReq(&packet);
    CHECK(checks==2 && receiver.rx_req_pkt_q.size()==1); // Duplicates cannot reserve a second slot.
    receiver.freePDC(); CHECK(loop.pending()==0);
}

struct Fixture {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    Fabric::Port& first_port; Fabric::Port& second_port; Fabric::Port& target_port;
    PdsHost first_host,second_host,target_host;
    Endpoint first,second,target;
    Region region;
    size_t resource_nacks=0,unallocated_nacks=0;
    std::set<uint32_t> write_sequences,error_sequences,guaranteed_errors;
    explicit Fixture(bool congestion=false)
        :first_port(fabric.add_host(1)),second_port(fabric.add_host(3)),target_port(fabric.add_host(2)),
         first_host(1,loop,trace,first_port),second_host(3,loop,trace,second_port),target_host(2,loop,trace,target_port),
         first(1,first_host,loop,trace,64,1000*kMillisecond),
         second(3,second_host,loop,trace,64,1000*kMillisecond),
         target(2,target_host,loop,trace,64,1000*kMillisecond,nullptr,8,1) {
        for (const auto peer:{1u,3u}) { fabric.add_link(peer,2,{}); fabric.add_link(2,peer,{}); }
        if (congestion) {
            const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,256);
            first_host.enable_nscc(config); second_host.enable_nscc(config); target_host.enable_nscc(config);
        }
        first.memory().add_job(1); second.memory().add_job(1); target.memory().add_job(1);
        region=target.memory().register_region(1,1,512,7);
        fabric.set_capture([this](Time,const Frame& frame) {
            const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
            if (frame.source==3 && packet.PDS_type==RUOD_req_header &&
                packet.SESpkt.bth_header.Standard_Header.opcode==1)
                write_sequences.insert(packet.PDS_header.RUOD_req_header.psn);
            if (frame.source!=2 || frame.destination!=3) return;
            if (packet.PDS_type==nack_header && packet.PDS_header.nack_header.nack_code==UET_NO_SES_MSG_AVAIL) {
                ++resource_nacks; unallocated_nacks+=packet.PDS_header.nack_header.spdcid==0;
            }
            if (packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE &&
                packet.SESpkt.bth_header.Semantic_Response_Header.return_code!=1) {
                const auto& ack=packet.PDS_header.RUOD_ack_header;
                const uint32_t sequence=ack.cack_psn+ack.ack_psn_off; error_sequences.insert(sequence);
                if (ack.flags.req&1) guaranteed_errors.insert(sequence);
            }
        });
    }
    void fill_slot() {
        Operation send; send.type=OperationType::Send; send.peer=2; send.delivery_mode=ROD; send.payload.assign(64,0x22);
        first.submit(send); loop.run_until(100000);
        CHECK(target.retained_receive_messages()==1 && target.unexpected_bytes()==64);
    }
    void post_filler_receive() { target.post_receive(1,1,region.key,0,64,101); }
    Operation write(bool bad_key) {
        Operation operation; operation.type=OperationType::Write; operation.peer=2; operation.delivery_mode=RUD;
        operation.remote_key=bad_key?0:region.key; operation.remote_offset=128; operation.payload.assign(128,0x5a);
        return operation;
    }
    void close() {
        first.close(); second.close(); target.close(); first_host.close(); second_host.close(); target_host.close();
        CHECK(loop.pending()==0);
    }
};

void admission_recovers(bool congestion,bool preopened,bool bad_key) {
    Fixture test(congestion);
    if (preopened) { CHECK(test.second_host.open_connection(2,1,RUD)!=UINT16_MAX); test.loop.run_until(50000); }
    test.fill_slot(); const auto open_before=test.target_host.manager().getPDSStatus().open_cnt;
    const auto write=test.write(bad_key); const auto operation=test.second.submit(write);
    test.loop.run_until(200000);
    Completion completion{};
    CHECK(!test.second.poll_completion(completion) && !test.first.poll_completion(completion));
    CHECK(test.resource_nacks>=2 && test.error_sequences.empty());
    CHECK((test.unallocated_nacks>0)==!preopened);
    CHECK(test.target_host.manager().getPDSStatus().open_cnt==open_before && test.target.retained_receive_messages()==1);
    CHECK(test.target.memory().read(1,1,test.region.key,128,128)==std::vector<uint8_t>(128,0));
    test.post_filler_receive(); test.loop.run(100000);
    CHECK(test.first.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(test.target.poll_completion(completion) && completion.context==101 && completion.status==CompletionStatus::Success);
    CHECK(test.second.poll_completion(completion) && completion.operation==operation);
    CHECK(completion.status==(bad_key?CompletionStatus::RemoteError:CompletionStatus::Success));
    CHECK(test.write_sequences.size()==2); // Resource retries keep the original PSNs.
    if (bad_key) CHECK(completion.remote_code==0x1c && test.error_sequences.size()==2 && test.guaranteed_errors.size()==1);
    const auto expected=bad_key?std::vector<uint8_t>(128,0):write.payload;
    CHECK(test.target.memory().read(1,1,test.region.key,128,128)==expected);
    CHECK(test.target.retained_receive_messages()==0);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2; noop.delivery_mode=RUD;
    test.second.submit(noop); test.loop.run(100000); // The same PDC remains usable after idle cleanup.
    CHECK(test.second.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(!test.first.poll_completion(completion) && !test.second.poll_completion(completion) && !test.target.poll_completion(completion));
    CHECK(test.target.retained_receive_messages()==0 && test.first.leased_message_ids()==0 && test.second.leased_message_ids()==0);
    test.close();
}

void permanent_pressure_is_bounded() {
    Fixture test; test.first_host.configure_retry_limit(15); test.fill_slot();
    test.second.submit(test.write(false)); test.loop.run_until(100*kMillisecond,100000);
    Completion completion{};
    CHECK(test.second.poll_completion(completion) && completion.status==CompletionStatus::Timeout);
    CHECK(!test.second.poll_completion(completion) && !test.first.poll_completion(completion));
    CHECK(test.error_sequences.empty() && test.resource_nacks>0 && test.unallocated_nacks==test.resource_nacks);
    CHECK(test.target.retained_receive_messages()==1 && test.target_host.manager().getPDSStatus().open_cnt==1);
    CHECK(test.target.memory().read(1,1,test.region.key,128,128)==std::vector<uint8_t>(128,0));
    test.post_filler_receive(); test.loop.run(100000);
    CHECK(test.first.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(test.target.poll_completion(completion) && completion.context==101);
    CHECK(test.target.retained_receive_messages()==0); test.close();
}

void failed_context_creation_returns_the_reservation() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source=fabric.add_host(1); auto& destination=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost host(2,loop,trace,destination); Endpoint target(2,host,loop,trace); target.memory().add_job(1);
    host.services().next_pdc_incarnation=UINT64_MAX; // Local context identity resources are exhausted.
    std::vector<PDStoNET_pkt> replies;
    source.set_receiver([&](Frame frame) { replies.push_back(UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet); });
    auto packet=request_packet(0,1,1,RUD); packet.PDS_header.RUOD_req_header.flags.syn=1;
    WireOptions wire; wire.source.ip[3]=1; wire.destination.ip[3]=2;
    Frame frame; frame.source=1; frame.destination=2; frame.bytes=UetWireCodec::encode(packet,wire);
    CHECK(source.try_send(frame)==SendResult::Accepted); loop.run(100000);
    CHECK(replies.size()==1 && replies.front().PDS_type==nack_header);
    CHECK(replies.front().PDS_header.nack_header.nack_code==UET_NO_PDC_AVAIL && !replies.front().PDS_header.nack_header.spdcid);
    CHECK(host.manager().getPDSStatus().open_cnt==0 && target.retained_receive_messages()==0);
    target.close(); host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) { kernel_admission<I_PDC>(mode); kernel_admission<T_PDC>(mode); }
        for (const bool congestion:{false,true}) for (const bool preopened:{false,true})
            for (const bool bad_key:{false,true}) admission_recovers(congestion,preopened,bad_key);
        permanent_pressure_is_bounded(); failed_context_creation_returns_the_reservation();
        std::cout<<"PASS SES credit admission, no false receipt/context, retries, first-error guarantee and rollback\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
