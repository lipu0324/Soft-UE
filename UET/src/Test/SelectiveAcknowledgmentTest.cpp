#include "Check.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

PDStoNET_pkt selective_ack(uint32_t sequence,uint32_t cumulative,uint16_t message,
                          uint8_t semantic_opcode=3,uint8_t return_code=0) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_ack_header;
    auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
    acknowledgment.type=ACK_CC; acknowledgment.next_hdr=UET_HDR_RESPONSE;
    acknowledgment.cack_psn=cumulative; acknowledgment.ack_psn_off=static_cast<int16_t>(sequence-cumulative);
    acknowledgment.spdcid=512; acknowledgment.dpdcid=1;
    packet.SESpkt.bth_type=Semantic_Response_Header;
    auto& semantic=packet.SESpkt.bth_header.Semantic_Response_Header;
    semantic.opcode=semantic_opcode; semantic.return_code=return_code;
    semantic.message_id=message;
    return packet;
}

void receipt_is_not_semantic_success(uint32_t first_sequence) {
    EventLoop loop; Services services{loop,loop,[]{}}; services.standard_wire=true;
    I_PDC sender(&services); CHECK(sender.initPDC(1,first_sequence)); sender.src_fep=1; sender.dst_fep=2;
    PDS_PDC_req request{}; request.next_hdr=UET_HDR_REQUEST_STD; request.delivery_mode=RUD;
    request.som=request.eom=true; request.pkt.bth_type=Standard_Header;
    auto& semantic=request.pkt.bth_header.Standard_Header;
    semantic.som=semantic.eom=semantic.dc=1; semantic.opcode=1; semantic.request_length=64;
    semantic.job_id=7; semantic.ri_generation=9;
    for (uint16_t message=1;message<=3;++message) { semantic.msg_id=message; sender.sesTxReq(&request); }
    while (!sender.tx_pkt_q.empty()) sender.tx_pkt_q.pop(); sender.gen_cm=NONE;
    PDStoNET_pkt clear_request{}; clear_request.PDS_type=RUOD_cp_header;
    clear_request.PDS_header.RUOD_cp_header.ctl_type=Clear_req;
    clear_request.PDS_header.RUOD_cp_header.payload=first_sequence+2;
    sender.state=ESTABLISHED; sender.rxCtrlClearReq(&clear_request);
    CHECK(sender.clear_psn==first_sequence-1 && sender.unack_cnt==3 && sender.tx_pkt_buffer.size()==3);
    CHECK(sender.rto_timer_.getActiveTimerCount()==3);
    sender.txCtrl(); CHECK(sender.tx_pkt_q.size()==1);
    CHECK(sender.tx_pkt_q.front().PDS_header.RUOD_cp_header.ctl_type==Clear_cmd);
    CHECK(sender.tx_pkt_q.front().PDS_header.RUOD_cp_header.payload==first_sequence-1);
    sender.tx_pkt_q.pop();
    auto first=selective_ack(first_sequence,first_sequence,1);
    const uint32_t base=first_sequence&~uint32_t{7};
    first.congestion_ack.sack_psn_offset=static_cast<int16_t>(base-first_sequence);
    first.congestion_ack.sack_bitmap=uint64_t{1}<<(first_sequence+2-base);
    sender.rxAck(&first);
    CHECK(sender.clear_psn==first_sequence-1 && sender.unack_cnt==3);
    CHECK(sender.tx_pkt_map.at(first_sequence+2).delivery_confirmed);
    CHECK(sender.rx_rsp_pkt_q.empty()); // SACK and equal CACK cannot infer DEFAULT.
    sender.txRto(first_sequence+2);
    CHECK(sender.tx_pkt_q.size()==1 && sender.tx_pkt_q.front().PDS_type==RUOD_cp_header);
    const auto& query=sender.tx_pkt_q.front().PDS_header.RUOD_cp_header;
    CHECK(query.ctl_type==ACK_req && query.psn==first_sequence+2 && query.payload==(3u<<16));
    sender.tx_pkt_q.pop();
    auto next=selective_ack(first_sequence+1,first_sequence+1,2);
    sender.rxAck(&next);
    CHECK(sender.clear_psn==first_sequence && sender.unack_cnt==2);
    CHECK(sender.rx_rsp_pkt_q.size()==1);
    const auto& inferred=sender.rx_rsp_pkt_q.front().pkt.bth_header.Semantic_Response_Header;
    CHECK(inferred.opcode==0 && inferred.return_code==1 && inferred.job_id==7 && inferred.message_id==1);
    sender.rx_rsp_pkt_q.pop();
    auto queried=selective_ack(first_sequence+2,first_sequence+1,3,0,1);
    sender.rxAck(&queried);
    CHECK(sender.clear_psn==first_sequence && sender.unack_cnt==1);
    CHECK(sender.rx_rsp_pkt_q.size()==1);
    const auto& scoped=sender.rx_rsp_pkt_q.front().pkt.bth_header.Semantic_Response_Header;
    CHECK(scoped.job_id==7 && scoped.ri_generation==9 && scoped.modified_length==0);
    sender.rx_rsp_pkt_q.pop(); sender.rxAck(&queried); CHECK(sender.rx_rsp_pkt_q.empty());
    auto error=selective_ack(first_sequence+1,first_sequence+1,2,1,6);
    error.SESpkt.bth_header.Semantic_Response_Header.job_id=7;
    sender.rxAck(&error);
    CHECK(sender.clear_psn==first_sequence+2 && sender.unack_cnt==0 && sender.rx_rsp_pkt_q.size()==1);
    CHECK(sender.rx_rsp_pkt_q.front().pkt.bth_header.Semantic_Response_Header.return_code==6);
    sender.freePDC(); CHECK(loop.pending()==0);
}

class SelectiveTarget : public T_PDC {
public:
    using T_PDC::T_PDC;
    using PDC::completed_rx_psns_;
    using PDC::received_rx_psns_;
};

void idle_default_ack_clears_without_a_request(uint32_t initial,pdc_mode mode,bool queued_request) {
    EventLoop loop; Services services{loop,loop,[]{}};
    I_PDC source(&services); CHECK(source.initPDC(1,initial));
    source.state=ESTABLISHED; source.SYN=0; source.DPDCID=512;
    PDS_PDC_req request{}; request.next_hdr=UET_HDR_REQUEST_STD; request.delivery_mode=mode;
    request.som=request.eom=true; request.pkt.bth_type=Standard_Header;
    auto& semantic=request.pkt.bth_header.Standard_Header;
    semantic.opcode=0; semantic.som=semantic.eom=semantic.dc=1; semantic.job_id=7; semantic.msg_id=1;
    source.sesTxReq(&request); CHECK(source.tx_pkt_q.size()==1); source.tx_pkt_q.pop(); source.gen_cm=NONE;
    if (queued_request) { semantic.msg_id=2; source.tx_req_q.push(request); }
    auto response=selective_ack(initial,initial,1,0,1); response.SESpkt.bth_header.Semantic_Response_Header.job_id=7;
    CHECK(!response.PDS_header.RUOD_ack_header.flags.req);
    source.rxAck(&response); CHECK(source.clear_psn==initial && source.tx_pkt_buffer.empty());
    if (queued_request) {
        CHECK(source.gen_cm==NONE); source.openChk(); CHECK(source.tx_pkt_q.size()==1);
        const auto& data=source.tx_pkt_q.front(); CHECK(data.PDS_type==RUOD_req_header);
        CHECK(uint32_t(data.PDS_header.RUOD_req_header.psn+data.PDS_header.RUOD_req_header.clear_psn_off)==initial);
    } else {
        CHECK(source.gen_cm==CLR_CMD); source.txCtrl(); CHECK(source.tx_pkt_q.size()==1);
        const auto clear=source.tx_pkt_q.front(); source.tx_pkt_q.pop();
        CHECK(clear.PDS_type==RUOD_cp_header && clear.PDS_header.RUOD_cp_header.ctl_type==Clear_cmd);
        CHECK(!clear.PDS_header.RUOD_cp_header.psn && !clear.PDS_header.RUOD_cp_header.flags.ar);
        CHECK(clear.PDS_header.RUOD_cp_header.payload==initial);
        SelectiveTarget target(&services); CHECK(target.initPDC(MAX_PDC)); target.state=ESTABLISHED;
        target.rx_cur_psn=target.cack_psn=initial; target.rx_clear_psn=initial-1;
        auto delivered=clear; target.rxCtrlClearCmd(&delivered);
        CHECK(target.rx_clear_psn==initial && target.tx_pkt_q.empty());
        source.rxAck(&response); CHECK(source.gen_cm==NONE && source.tx_pkt_q.empty());
        target.freePDC();
    }
    source.freePDC(); CHECK(loop.pending()==0);
}

void selective_bitmap_only_covers_processed_requests() {
    EventLoop loop; Services services{loop,loop,[]{}}; services.standard_wire=true;
    SelectiveTarget target(&services); CHECK(target.initPDC(MAX_PDC));
    target.mode=RUD; target.cack_psn=1000;
    target.completed_rx_psns_.insert(1001);
    target.received_rx_psns_.insert(1002); // SES has not returned a response.
    SEStoPDS_pkt response{}; response.bth_type=Semantic_Response_Header;
    response.bth_header.Semantic_Response_Header.opcode=1;
    target.sendAck(UET_HDR_RESPONSE,0,0,1003,&response,true);
    const auto& packet=target.tx_pkt_q.front();
    CHECK(packet.PDS_header.RUOD_ack_header.type==ACK_CC);
    CHECK(packet.congestion_ack.sack_psn_offset==0);
    CHECK(packet.congestion_ack.sack_bitmap==0b1010); // LSB bit 1 and bit 3.
    target.tx_pkt_q.pop();
    CHECK(target.replaySemanticAck(1003));
    CHECK(target.tx_pkt_q.front().congestion_ack.sack_bitmap==0b1010);
    target.tx_pkt_q.pop();
    target.rx_cur_psn=1003; target.rx_clear_psn=1000;
    target.completed_rx_psns_.insert(1002); // SES has now finished this packet.
    PDStoNET_pkt clear{}; clear.PDS_type=RUOD_cp_header;
    clear.PDS_header.RUOD_cp_header.ctl_type=Clear_cmd;
    clear.PDS_header.RUOD_cp_header.payload=1003;
    target.rxCtrlClearCmd(&clear);
    CHECK(target.cack_psn==1003 && target.tx_ack_buffer.empty() && target.tx_pkt_q.empty());
    target.freePDC(); CHECK(loop.pending()==0);
}

// Delay a middle fragment while EOM is already at the receiver. Its explicit
// NO_RESPONSE will be promoted by ACK Request before the hole is repaired.
class GapPort final : public IPacketPort {
public:
    GapPort(IPacketPort& lower,EventLoop& loop,bool permanent):lower_(lower),loop_(loop),permanent_(permanent) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header) {
            const auto& request=packet.SESpkt.bth_header.Standard_Header;
            if (!request.som && request.diff.som_false.message_offset==16 && loop_.now()<3*kMillisecond) {
                if (!permanent_) loop_.at(3*kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
                return SendResult::Accepted;
            }
            if (permanent_ && !request.som && request.diff.som_false.message_offset==16) return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; EventLoop& loop_; bool permanent_;
};

class FeedbackAuditPort final : public IPacketPort {
public:
    explicit FeedbackAuditPort(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE) {
            const auto& semantic=packet.SESpkt.bth_header.Semantic_Response_Header;
            if (semantic.opcode==0 && semantic.job_id==0) ++query_defaults;
            if (drop_first_error && semantic.opcode==1 && semantic.return_code!=1) {
                drop_first_error=false; ++dropped_errors; return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    size_t query_defaults=0,dropped_errors=0;
    bool drop_first_error=false;
private:
    IPacketPort& lower_;
};

class RequestAuditPort final : public IPacketPort {
public:
    explicit RequestAuditPort(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header) {
            const auto sequence=packet.PDS_header.RUOD_req_header.psn;
            if (!first_sequence) first_sequence=sequence;
            if (sequence==*first_sequence) ++first_data_attempts;
        }
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==ACK_req &&
            first_sequence && packet.PDS_header.RUOD_cp_header.psn==*first_sequence) ++first_response_queries;
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    size_t first_data_attempts=0,first_response_queries=0;
    std::optional<uint32_t> first_sequence;
private:
    IPacketPort& lower_;
};

void end_default_cannot_hide_a_gap(bool permanent,bool congestion) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    GapPort gaps(forward,loop,permanent); FeedbackAuditPort feedback(reverse);
    PdsHost source_host(1,loop,trace,gaps),target_host(2,loop,trace,feedback);
    source_host.services().rto_ns=UET::Runtime::kMillisecond;
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,128);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(7); target.memory().add_job(7);
    const auto region=target.memory().register_region(7,1,48,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.job=7;
    write.delivery_mode=RUD; write.remote_key=region.key; write.payload.assign(48,0x5a);
    source.submit(write);
    loop.run_until(2500*1000,100000);
    Completion completion{}; CHECK(!source.poll_completion(completion));
    CHECK(feedback.query_defaults>0); // An actual DEFAULT arrived before the missing data.
    CHECK(target.memory().read(7,1,region.key,16,16)==std::vector<uint8_t>(16,0));
    loop.run(100000);
    CHECK(source.poll_completion(completion));
    CHECK(completion.status==(permanent?CompletionStatus::Timeout:CompletionStatus::Success));
    CHECK(!source.poll_completion(completion));
    if (!permanent) CHECK(target.memory().read(7,1,region.key,0,48)==write.payload);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

void lost_guaranteed_error_is_queried_after_selective_receipt(bool congestion) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    RequestAuditPort requests(forward); FeedbackAuditPort feedback(reverse); feedback.drop_first_error=true;
    PdsHost source_host(1,loop,trace,requests),target_host(2,loop,trace,feedback);
    source_host.services().rto_ns=UET::Runtime::kMillisecond;
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,128);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(7); target.memory().add_job(7);
    const auto region=target.memory().register_region(7,1,16,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.job=7; write.delivery_mode=RUD;
    write.remote_key=region.key+1; write.payload.assign(16,0x5a);
    const auto rejected=source.submit(write);
    write.remote_key=region.key; const auto accepted=source.submit(write);
    loop.run_until(500*1000,100000);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.operation==accepted && completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion)); // SACK for the first packet cannot turn its missing error into success.
    loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.operation==rejected && completion.status==CompletionStatus::RemoteError);
    CHECK(feedback.dropped_errors==1 && requests.first_data_attempts==1 && requests.first_response_queries>0);
    CHECK(!source.poll_completion(completion) && source.leased_message_ids()==0 && target.retained_receive_messages()==0);
    CHECK(target.memory().read(7,1,region.key,0,16)==write.payload);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        receipt_is_not_semantic_success(1000);
        receipt_is_not_semantic_success(UINT32_MAX-1);
        selective_bitmap_only_covers_processed_requests();
        for (const uint32_t initial:{1000u,UINT32_MAX}) for (const auto mode:{RUD,ROD})
            for (const bool queued:{false,true}) idle_default_ack_clears_without_a_request(initial,mode,queued);
        for (bool congestion:{false,true}) {
            for (bool permanent:{false,true}) end_default_cannot_hide_a_gap(permanent,congestion);
            lost_guaranteed_error_is_queried_after_selective_receipt(congestion);
        }
        std::cout<<"PASS SACK receipt, strict CACK default inference, scoped response query, wrap and incomplete-message safety\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
