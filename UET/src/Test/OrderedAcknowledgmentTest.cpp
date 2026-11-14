#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <set>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

class InspectableResponder : public T_PDC {
public:
    using T_PDC::T_PDC;
    using PDC::pending_ordered_acknowledgments_;
};
uint32_t acknowledgment_sequence(const PDStoNET_pkt& packet) {
    CHECK(packet.PDS_type==RUOD_ack_header);
    return packet.PDS_header.RUOD_ack_header.cack_psn+packet.PDS_header.RUOD_ack_header.ack_psn_off;
}
void completed_responses_wait_for_earlier_psns(uint32_t first) {
    EventLoop loop; Services services{loop,loop,[]{}};
    InspectableResponder target(&services); CHECK(target.initPDC(MAX_PDC));
    target.start_psn=first; target.mode=ROD; target.state=ESTABLISHED;
    target.cack_psn=target.rx_clear_psn=first-1; target.rx_cur_psn=first+2;
    SEStoPDS_pkt response{}; response.bth_type=Semantic_Response_Header;
    response.bth_header.Semantic_Response_Header.opcode=1;
    response.bth_header.Semantic_Response_Header.return_code=1;
    target.sendAck(UET_HDR_RESPONSE,0,0,first+2,&response,true);
    CHECK(target.tx_pkt_q.empty() && target.pending_ordered_acknowledgments_.size()==1);
    PDStoNET_pkt query{}; query.PDS_type=RUOD_cp_header; query.wire_entropy=0x4242;
    query.PDS_header.RUOD_cp_header.ctl_type=ACK_req;
    query.PDS_header.RUOD_cp_header.flags.ar=1; query.PDS_header.RUOD_cp_header.psn=first+2;
    target.rxCtrlAckReq(&query); // A ready cache entry cannot bypass the first-ACK ordering barrier.
    CHECK(target.tx_pkt_q.empty() && target.pending_ordered_acknowledgments_.size()==1);
    target.sendAck(UET_HDR_RESPONSE,0,0,first+1,&response,false);
    CHECK(target.tx_pkt_q.empty() && target.pending_ordered_acknowledgments_.size()==2);
    target.sendAck(UET_HDR_RESPONSE,0,0,first,&response,true);
    CHECK(target.tx_pkt_q.size()==3 && target.pending_ordered_acknowledgments_.empty());
    for (unsigned offset=0;offset<3;++offset) {
        CHECK(acknowledgment_sequence(target.tx_pkt_q.front())==uint32_t(first+offset));
        target.tx_pkt_q.pop();
    }
    target.rxCtrlAckReq(&query);
    CHECK(target.tx_pkt_q.size()==1 && acknowledgment_sequence(target.tx_pkt_q.front())==uint32_t(first+2));
    CHECK(target.tx_pkt_q.front().wire_entropy==0x4242); target.tx_pkt_q.pop();
    // A delayed duplicate of an already emitted ACK remains replayable. The
    // monotonic frontier orders first responses, not historical recovery ACKs.
    target.freePDC(); CHECK(loop.pending()==0);
    CHECK(target.initPDC(MAX_PDC)); target.start_psn=7; target.mode=ROD;
    target.sendAck(UET_HDR_RESPONSE,0,0,9,&response,true);
    CHECK(target.pending_ordered_acknowledgments_.size()==1); target.freePDC();
    CHECK(target.pending_ordered_acknowledgments_.empty());
    CHECK(target.initPDC(MAX_PDC)); target.start_psn=17; target.mode=ROD;
    target.sendAck(UET_HDR_RESPONSE,0,0,17,&response,false);
    CHECK(target.tx_pkt_q.size()==1 && acknowledgment_sequence(target.tx_pkt_q.front())==17);
    target.freePDC(); CHECK(loop.pending()==0);
}

void unordered_responses_remain_independent() {
    EventLoop loop; Services services{loop,loop,[]{}};
    InspectableResponder target(&services); CHECK(target.initPDC(MAX_PDC)); target.mode=RUD;
    target.sendAck(UET_HDR_NONE,0,0,1002,nullptr,false);
    CHECK(target.tx_pkt_q.size()==1 && acknowledgment_sequence(target.tx_pkt_q.front())==1002);
    CHECK(target.pending_ordered_acknowledgments_.empty()); target.freePDC();
}

void deferred_send_orders_following_write_acks(bool congestion,bool ipv6,bool udp,bool preopen) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    WireOptions network; network.ipv6=ipv6; network.udp=udp; network.native_ip_protocol=253;
    PdsHost source_host(1,loop,trace,forward,PdsHost::WireFormat::Uet11,network);
    PdsHost target_host(2,loop,trace,reverse,PdsHost::WireFormat::Uet11,network);
    source_host.configure_retransmission_timeout(10*kMillisecond);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,2),target(2,target_host,loop,trace,2);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,32,7);
    if (preopen) { CHECK(source_host.open_connection(2,1,ROD,true)!=UINT16_MAX); loop.run_until(10000); }
    std::vector<uint32_t> requests,acknowledgments; std::set<uint16_t> finished_messages;
    std::set<uint32_t> acknowledged_sequences;
    std::optional<uint16_t> data_context;
    std::vector<uint8_t> response_codes;
    std::vector<unsigned> request_opcodes;
    std::optional<uint16_t> current_message;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),true,253).packet;
        if (frame.source==1 && packet.PDS_type==RUOD_req_header) {
            const auto local_context=packet.PDS_header.RUOD_req_header.spdcid;
            if (!data_context) data_context=local_context;
            CHECK(*data_context==local_context);
            const auto& semantic=packet.SESpkt.bth_header.Standard_Header;
            request_opcodes.push_back(semantic.opcode);
            if (current_message!=semantic.msg_id) {
                if (current_message) finished_messages.insert(*current_message);
                CHECK(!finished_messages.count(semantic.msg_id)); current_message=semantic.msg_id;
                CHECK(semantic.som);
            }
            requests.push_back(packet.PDS_header.RUOD_req_header.psn);
        } else if (frame.source==2 && packet.PDS_type==RUOD_ack_header && !packet.PDS_header.RUOD_ack_header.flags.p &&
                   data_context && packet.PDS_header.RUOD_ack_header.dpdcid==*data_context) {
            const auto sequence=acknowledgment_sequence(packet);
            // Ordering applies to first responses. An earlier ACK can be
            // replayed for query/duplicate recovery after newer ACKs exist.
            if (acknowledged_sequences.insert(sequence).second) acknowledgments.push_back(sequence);
            response_codes.push_back(packet.SESpkt.bth_header.Semantic_Response_Header.return_code);
        }
    });
    Operation send; send.type=OperationType::Send; send.peer=2; send.payload={1,2,3,4,5}; source.submit(send);
    Operation first_write; first_write.type=OperationType::Write; first_write.peer=2;
    first_write.remote_key=region.key; first_write.remote_offset=8; first_write.payload={6,7,8,9,10,11}; source.submit(first_write);
    auto second_write=first_write; second_write.remote_offset=16; second_write.payload={12,13,14}; source.submit(second_write);
    loop.run_until(500000);
    if (requests.size()!=8 || acknowledgments.size()!=2) {
        std::cerr<<"response codes:"; for (auto code:response_codes) std::cerr<<' '<<unsigned(code); std::cerr<<'\n';
        std::cerr<<"request opcodes:"; for (auto code:request_opcodes) std::cerr<<' '<<code; std::cerr<<" unexpected="<<target.unexpected_bytes()<<'\n';
        std::cerr<<"request PSNs:"; for (auto psn:requests) std::cerr<<' '<<psn; std::cerr<<'\n';
        std::cerr<<"ACK PSNs:"; for (auto psn:acknowledgments) std::cerr<<' '<<psn; std::cerr<<'\n';
        throw std::runtime_error("delayed SEND: requests="+std::to_string(requests.size())+
            ", ACKs="+std::to_string(acknowledgments.size())+", nscc="+std::to_string(congestion)+
            ", ipv6="+std::to_string(ipv6)+", udp="+std::to_string(udp)+", preopen="+std::to_string(preopen));
    }
    // Two intermediate SEND defaults; EOM waits for placement.
    CHECK(target.memory().read(1,1,region.key,8,6)==first_write.payload);
    CHECK(target.memory().read(1,1,region.key,16,3)==second_write.payload);
    Completion completion{}; CHECK(!source.poll_completion(completion));
    target.post_receive(1,1,region.key,0,5); loop.run_until(kMillisecond);
    CHECK(acknowledgments==requests);
    size_t completions=0;
    while (source.poll_completion(completion)) { CHECK(completion.status==CompletionStatus::Success); ++completions; }
    CHECK(completions==3 && target.memory().read(1,1,region.key,0,5)==send.payload);
    CHECK(target.retained_receive_messages()==0 && source.leased_message_ids()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}
int main() {
    try {
        completed_responses_wait_for_earlier_psns(1000); completed_responses_wait_for_earlier_psns(UINT32_MAX-1);
        unordered_responses_remain_independent();
        for (const bool congestion:{false,true}) for (const bool ipv6:{false,true})
            for (const bool udp:{false,true}) for (const bool preopen:{false,true})
                deferred_send_orders_following_write_acks(congestion,ipv6,udp,preopen);
        std::cout<<"PASS first ROD ACK ordering, cached-query barriers, delayed SEND, FIFO fragments, wrap and reuse\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
