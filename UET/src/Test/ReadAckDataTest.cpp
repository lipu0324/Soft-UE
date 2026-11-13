#include "Check.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/Fabric.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

// Observe the actual protocol frames. Loss is confined to this packet port;
// PDS, rather than a reliable test backend, must recover the READ.
class ReadAuditPort final : public IPacketPort {
public:
    explicit ReadAuditPort(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto& packet=decoded.packet;
        packets.push_back(packet);
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            packet.SESpkt.bth_header.Standard_Header.opcode==2) {
            const auto& request=packet.SESpkt.bth_header.Standard_Header;
            CHECK(packet.SESpkt.payload.empty()); CHECK(request.som && request.eom);
            CHECK(frame.bytes[54]==2); // Ethernet(14)+IPv4(20)+UDP(8)+PDS request(12).
            ++read_attempts;
            if (read_sequence) CHECK(*read_sequence==packet.PDS_header.RUOD_req_header.psn);
            else read_sequence=packet.PDS_header.RUOD_req_header.psn;
            if (drop_read && read_attempts==1) return SendResult::Accepted;
        }
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==ACK_req) ++queries;
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header) {
            const auto& data=packet.SESpkt.bth_header.Semantic_Response_with_Data_Header;
            const size_t semantic_offset=42+(packet.PDS_header.RUOD_ack_header.type==ACK_CC?32:12);
            CHECK(frame.bytes[semantic_offset]==2 && frame.bytes[semantic_offset+1]==1);
            CHECK((packet.PDS_header.RUOD_ack_header.flags.req&1)!=0);
            CHECK(data.payload_length==packet.SESpkt.payload.size());
            ++data_responses;
            if (on_data) on_data(packet);
            if (drop_data && data_responses==1) return SendResult::Accepted;
            if (malformed_data && data_responses==1) {
                auto altered=packet;
                auto& result=altered.SESpkt.bth_header.Semantic_Response_with_Data_Header;
                switch (malformed_data) {
                case 1: result.job_id^=1; break;
                case 2: result.read_request_msg_id^=1; break;
                case 3: ++result.payload_length; break;
                case 4: ++result.modified_length; break;
                case 5: result.message_offset=1; break;
                case 6: {
                    const auto read_id=result.read_request_msg_id;
                    const auto job=result.job_id;
                    altered.PDS_header.RUOD_ack_header.next_hdr=UET_HDR_RESPONSE;
                    altered.SESpkt={}; altered.SESpkt.bth_type=Semantic_Response_Header;
                    auto& empty=altered.SESpkt.bth_header.Semantic_Response_Header;
                    empty.opcode=0; empty.return_code=1; empty.message_id=read_id; empty.job_id=job;
                    break;
                }
                default: throw std::logic_error("unknown READ response fault");
                }
                auto changed_frame=frame;
                changed_frame.bytes=UetWireCodec::encode(altered,decoded.network);
                return lower_.try_send(changed_frame);
            }
            if (duplicate_data && data_responses==1) CHECK(lower_.try_send(frame)==SendResult::Accepted);
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool drop_read=false,drop_data=false,duplicate_data=false;
    uint8_t malformed_data=0;
    size_t read_attempts=0,data_responses=0,queries=0;
    std::optional<uint32_t> read_sequence;
    std::function<void(const PDStoNET_pkt&)> on_data;
    std::vector<PDStoNET_pkt> packets;
private:
    IPacketPort& lower_;
};

void transfer(pdc_mode mode,bool congestion,uint32_t threshold,uint32_t length,
              bool lose_request=false,bool lose_response=false,bool duplicate=false,bool revoke_local=false,uint8_t malformed=0) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    ReadAuditPort forward(fabric.add_host(1)),reverse(fabric.add_host(2));
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(threshold); target_host.configure_read_ack_data(threshold);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,8300);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,8192),target(2,target_host,loop,trace,8192);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions local_options; local_options.requested_key=0x123456789abc;
    const auto local=source.memory().register_region(1,1,8200,Access::Read|Access::Write,local_options);
    const auto remote=target.memory().register_region(1,1,8200,Access::Read|Access::Write);
    std::vector<uint8_t> expected(length);
    for (size_t index=0;index<expected.size();++index) expected[index]=index*13+7;
    target.memory().write(1,1,remote.key,5,expected);
    forward.drop_read=lose_request; reverse.drop_data=lose_response; reverse.duplicate_data=duplicate;
    reverse.malformed_data=malformed;
    std::optional<Region> replacement;
    reverse.on_data=[&](const PDStoNET_pkt&) {
        if (reverse.data_responses!=1) return;
        if (lose_response) {
            // The target must re-execute, not replay the first snapshot.
            for (auto& byte:expected) byte^=0x5a;
            target.memory().write(1,1,remote.key,5,expected);
        }
        if (revoke_local) {
            CHECK(source.memory().deregister(local.key));
            RegionOptions options; options.requested_key=local.key;
            replacement=source.memory().register_region(1,1,8200,Access::Read|Access::Write,options);
        }
    };
    Operation read; read.type=OperationType::Read; read.peer=2; read.delivery_mode=mode;
    read.remote_key=remote.key; read.remote_offset=5; read.read_length=length; read.context=77;
    read.read_result=ReadResultBuffer{local.key,3,length,1,1};
    const auto operation=source.submit(read);
    // RUD's following packet advertises SACK for a READ whose ACK was lost.
    // Receipt confirmation must still lead to original-READ retransmission.
    Operation noop; noop.type=OperationType::Noop; noop.peer=2; noop.delivery_mode=mode;
    const auto following=source.submit(noop);
    loop.run(100000);
    Completion completion{}; size_t reads=0,noops=0;
    while (source.poll_completion(completion)) {
        if (completion.operation==operation) {
            ++reads; CHECK(completion.context==77);
            if (completion.status!=(revoke_local?CompletionStatus::LocalError:CompletionStatus::Success))
                std::cerr<<"READ failure mode="<<mode<<" nscc="<<congestion<<" length="<<length
                    <<" request_loss="<<lose_request<<" ack_loss="<<lose_response<<" duplicate="<<duplicate
                    <<" revoke="<<revoke_local<<" status="<<static_cast<int>(completion.status)
                    <<" code="<<static_cast<unsigned>(completion.remote_code)<<" attempts="<<forward.read_attempts
                    <<" responses="<<reverse.data_responses<<'\n';
            CHECK(completion.status==(revoke_local?CompletionStatus::LocalError:CompletionStatus::Success));
            CHECK(completion.length==(revoke_local?0:length));
        } else { CHECK(completion.operation==following && completion.status==CompletionStatus::Success); ++noops; }
    }
    CHECK(reads==1 && noops==1 && !target.poll_completion(completion));
    CHECK(forward.read_attempts==(lose_request||lose_response||malformed?2:1) && forward.queries==0);
    CHECK(reverse.data_responses==(lose_response||malformed?2:1));
    if (revoke_local) CHECK(source.memory().read(1,1,replacement->key,3,length)==std::vector<uint8_t>(length));
    else CHECK(source.memory().read(1,1,local.key,3,length)==expected);
    CHECK(source.memory().read(1,1,revoke_local?replacement->key:local.key,0,3)==std::vector<uint8_t>(3));
    CHECK(source.leased_message_ids()==0 && target.retained_receive_messages()==0);
    CHECK(std::none_of(trace.events().begin(),trace.events().end(),[](const auto& event) { return event.event=="malformed_frame"; }));
    if (congestion && mode==RUD && lose_response) {
        std::optional<uint32_t> first_counter;
        for (const auto& packet:reverse.packets) if (packet.PDS_type==RUOD_ack_header &&
            packet.SESpkt.bth_type==Semantic_Response_with_Data_Header) {
            if (!first_counter) first_counter=packet.congestion_ack.received_byte_units;
            // A NO_OP adds one original packet; the reissued READ adds none.
            CHECK(packet.congestion_ack.received_byte_units-*first_counter<=1);
        }
        size_t charged=0;
        for (const auto& event:trace.events()) if (event.node==1 && event.event=="nscc_inflight") ++charged;
        CHECK(charged==2); // READ plus NO_OP, no double debit for confirmed READ reissue.
    }
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

void local_and_remote_errors() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,9);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1); target.memory().add_job(2);
    const auto local=source.memory().register_region(1,1,32,Access::Read|Access::Write);
    const auto remote=target.memory().register_region(1,1,32,Access::Read|Access::Write);
    const auto write_only=target.memory().register_region(1,1,32,static_cast<uint8_t>(Access::Write));
    const auto foreign=target.memory().register_region(2,1,32,Access::Read|Access::Write);
    Operation read; read.type=OperationType::Read; read.peer=2; read.read_length=16; read.remote_key=remote.key;
    read.read_result=ReadResultBuffer{local.key,4,16,1,1};
    const auto check_local=[&](Operation invalid,CompletionStatus expected) {
        source.submit(std::move(invalid)); Completion completion{};
        CHECK(source.poll_completion(completion) && completion.status==expected);
        CHECK(!source.poll_completion(completion));
    };
    auto invalid=read; invalid.read_length=17; check_local(invalid,CompletionStatus::Unsupported);
    invalid=read; invalid.payload={1}; check_local(invalid,CompletionStatus::InvalidRequest);
    invalid=read; invalid.immediate_data=1; check_local(invalid,CompletionStatus::InvalidRequest);
    invalid=read; invalid.read_result.reset(); check_local(invalid,CompletionStatus::InvalidRequest);
    invalid=read; invalid.read_result->capacity=15; check_local(invalid,CompletionStatus::InvalidRequest);
    invalid=read; invalid.read_result->offset=25; check_local(invalid,CompletionStatus::LocalError);
    invalid=read; invalid.read_result->key^=0x100000; check_local(invalid,CompletionStatus::LocalError);
    CHECK(source_host.manager().getPDSStatus().open_cnt==0);
    for (const auto [key,offset,code]:{std::tuple{uint64_t{0},uint64_t{0},uint8_t{0x1c}},
            std::tuple{write_only.key,uint64_t{0},uint8_t{0x18}},std::tuple{foreign.key,uint64_t{0},uint8_t{0x17}},
            std::tuple{remote.key,uint64_t{20},uint8_t{0x1d}}}) {
        read.remote_key=key; read.remote_offset=offset; source.submit(read); loop.run(100000);
        Completion completion{}; CHECK(source.poll_completion(completion));
        CHECK(completion.status==CompletionStatus::RemoteError && completion.remote_code==code);
        CHECK(!source.poll_completion(completion));
        CHECK(source.memory().read(1,1,local.key,0,32)==std::vector<uint8_t>(32));
    }
    read.remote_key=remote.key; read.remote_offset=0; read.read_length=0; read.read_result.reset();
    source.submit(read); loop.run(100000);
    Completion empty{}; CHECK(source.poll_completion(empty) && empty.status==CompletionStatus::Success && !empty.length);
    CHECK(!source.poll_completion(empty));
    CHECK(source.capabilities().read && source.capabilities().max_read_length==16 && !source.capabilities().hpc);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

class ReadTarget : public T_PDC {
public:
    using T_PDC::T_PDC;
    size_t uncached_count() const { return uncached_read_responses_.size(); }
};

void query_and_clear(uint32_t initial_sequence,pdc_mode mode) {
    EventLoop loop; Services services{loop,loop,[]{}};
    ReadTarget target(&services); CHECK(target.initPDC(512)); target.setFep(1,2);
    PDStoNET_pkt request{}; request.PDS_type=RUOD_req_header;
    auto& delivery=request.PDS_header.RUOD_req_header;
    delivery.type=mode==RUD?RUD_REQ:ROD_REQ; delivery.next_hdr=UET_HDR_REQUEST_STD;
    delivery.flags.syn=delivery.flags.ar=1; delivery.psn=initial_sequence;
    delivery.clear_psn_off=-1; delivery.spdcid=1;
    request.SESpkt.bth_type=Standard_Header;
    auto& read=request.SESpkt.bth_header.Standard_Header;
    read.opcode=2; read.som=read.eom=read.dc=1; read.job_id=1; read.msg_id=9; read.request_length=16;
    target.netRxReq(&request); CHECK(target.rx_req_pkt_q.size()==1);
    const auto accepted=target.rx_req_pkt_q.front(); target.rx_req_pkt_q.pop();
    SES_PDC_rsp response{}; response.rx_pkt_handle=accepted.rx_pkt_handle;
    response.gtd_del=true; response.rep_len=36; response.pkt.bth_type=Semantic_Response_with_Data_Header;
    response.pkt.bth_header.Semantic_Response_with_Data_Header.opcode=2;
    response.pkt.payload.assign(16,7); target.sesTxRsp(&response);
    CHECK(target.tx_ack_buffer.empty() && target.uncached_count()==1 && target.cack_psn==initial_sequence-1);
    CHECK(target.tx_pkt_q.size()==1); target.tx_pkt_q.pop();
    PDStoNET_pkt query{}; query.PDS_type=RUOD_cp_header;
    auto& control=query.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=ACK_req; control.flags.ar=1;
    control.psn=initial_sequence; control.payload=9u<<16; control.spdcid=1; control.dpdcid=512;
    target.netRxCm(&query); CHECK(target.tx_pkt_q.size()==1);
    CHECK(target.tx_pkt_q.front().PDS_type==nack_header &&
        target.tx_pkt_q.front().PDS_header.nack_header.nack_code==UET_ACK_WITH_DATA);
    target.tx_pkt_q.pop();
    delivery.flags.syn=0; delivery.flags.retx=1; delivery.dpdcid=512;
    target.netRxReq(&request); CHECK(target.rx_req_pkt_q.size()==1);
    target.netRxCm(&query); CHECK(target.tx_pkt_q.size()==1);
    CHECK(target.tx_pkt_q.front().PDS_header.nack_header.nack_code==UET_RCVD_SES_PROCG);
    target.tx_pkt_q.pop();
    response.rx_pkt_handle=target.rx_req_pkt_q.front().rx_pkt_handle; target.rx_req_pkt_q.pop();
    target.sesTxRsp(&response); CHECK(target.tx_pkt_q.size()==1); target.tx_pkt_q.pop();
    control.ctl_type=Clear_cmd; control.flags.ar=0; control.payload=initial_sequence;
    target.netRxCm(&query);
    CHECK(target.cack_psn==initial_sequence && target.tx_ack_buffer.empty() && target.uncached_count()==0);
    target.netRxReq(&request); CHECK(target.rx_req_pkt_q.empty() && target.tx_pkt_q.empty());
    target.freePDC(); CHECK(loop.pending()==0);
}

void configuration_boundaries() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    PdsHost host(1,loop,trace,fabric.add_host(1));
    for (uint32_t threshold=0;threshold<=8192;threshold+=16) {
        host.configure_read_ack_data(threshold); CHECK(host.services().max_ack_data_size==threshold);
    }
    for (const uint32_t invalid:{1u,15u,17u,8193u,UINT32_MAX})
        check_throws<std::invalid_argument>([&] { host.configure_read_ack_data(invalid); });
    host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true}) {
            for (const uint32_t length:{0,1,15,16}) transfer(mode,congestion,16,length);
            transfer(mode,congestion,16,16,true);
            transfer(mode,congestion,16,16,false,true);
            transfer(mode,congestion,16,16,false,false,true);
            transfer(mode,congestion,16,16,false,false,false,true);
            transfer(mode,congestion,8192,8192);
            for (uint8_t malformed=1;malformed<=6;++malformed)
                transfer(mode,congestion,16,16,false,false,false,false,malformed);
        }
        transfer(RUD,false,0,0);
        for (const auto mode:{RUD,ROD}) for (const uint32_t sequence:{1u,UINT32_MAX}) query_and_clear(sequence,mode);
        configuration_boundaries();
        local_and_remote_errors();
        std::cout<<"PASS: ACK-data READ, zero/MTU boundaries, original-request reissue, MR authority and one completion\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
