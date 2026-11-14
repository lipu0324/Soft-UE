#include "Check.hpp"
#include "../Runtime/Runtime.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include <iostream>
#include <type_traits>
using namespace UET::Runtime;

class ReadReplayReceiver final : public T_PDC {
public:
    using T_PDC::T_PDC;
    using PDC::reissueReceivedRead;
    bool has_uncached_read(uint32_t sequence) const { return uncached_read_responses_.count(sequence); }
};

// A receiver has physical byte receipt before SES has a result. That fact
// permits SACK, but cannot justify Clear of an outstanding semantic handle.
template<class Receiver> void clear_waits_for_semantics(pdc_mode mode,uint32_t first,bool first_no_response) {
    EventLoop loop; std::vector<uint32_t> cleared;
    Services services{loop,loop,[] {}};
    services.pdc_event=[&](const PdcEvent& event) {
        if (event.kind==PdcEventKind::ReceiveCleared) cleared.push_back(event.sequence);
    };
    Receiver receiver(&services);
    CHECK(receiver.initPDC(std::is_same_v<Receiver,I_PDC>?1:MAX_PDC));
    receiver.state=ESTABLISHED; receiver.mode=mode; receiver.src_fep=2; receiver.dst_fep=1;
    receiver.start_psn=first; receiver.rx_clear_psn=receiver.cack_psn=first-1; receiver.rx_cur_psn=first+1;
    RX_pkt_meta metadata{}; metadata.psn=first; metadata.spdcid=1; metadata.som=true;
    receiver.rx_pkt_map.emplace(7,metadata); metadata.psn=first+1; receiver.rx_pkt_map.emplace(8,metadata);
    const auto clear=[&](uint32_t through) {
        PDStoNET_pkt control{}; control.PDS_type=RUOD_cp_header;
        control.PDS_header.RUOD_cp_header.ctl_type=Clear_cmd;
        control.PDS_header.RUOD_cp_header.payload=through;
        receiver.rxCtrlClearCmd(&control);
    };
    clear(first);
    CHECK(receiver.rx_clear_psn==uint32_t(first-1) && cleared.empty() && receiver.rx_pkt_map.size()==2);
    const auto respond=[&](ReceivePacketHandle handle,bool guaranteed,bool no_response=false) {
        SES_PDC_rsp result{}; result.rx_pkt_handle=handle; result.gtd_del=guaranteed; result.rep_len=12;
        result.pkt.bth_type=Semantic_Response_Header;
        auto& semantic=result.pkt.bth_header.Semantic_Response_Header;
        semantic.opcode=no_response?3:0; semantic.return_code=no_response?0:1;
        semantic.message_id=9; semantic.job_id=1; semantic.modified_length=no_response?0:4;
        receiver.txRsp(&result);
    };
    respond(7,false,first_no_response);
    clear(first+1); // The later packet is received but still processing.
    CHECK(receiver.rx_clear_psn==uint32_t(first-1) && cleared.empty());
    clear(first);
    CHECK(receiver.rx_clear_psn==first && cleared==std::vector<uint32_t>{first});
    respond(8,true);
    CHECK(receiver.tx_ack_buffer.count(first+1));
    clear(first+1); clear(first+1);
    CHECK(receiver.rx_clear_psn==uint32_t(first+1) && cleared==std::vector<uint32_t>({first,first+1}));
    CHECK(receiver.rx_pkt_map.empty() && receiver.tx_ack_buffer.empty() && receiver.cack_psn==uint32_t(first+1));
    receiver.freePDC(); CHECK(!loop.pending());
}
void clear_during_reissued_read(pdc_mode mode,uint32_t first) {
    EventLoop loop; size_t cleared=0;
    Services services{loop,loop,[] {}};
    services.receive_handle_allocator=ReceiveHandleAllocator(uint64_t{1}<<32);
    services.pdc_event=[&](const PdcEvent& event) { cleared+=event.kind==PdcEventKind::ReceiveCleared; };
    ReadReplayReceiver receiver(&services); CHECK(receiver.initPDC(MAX_PDC));
    receiver.state=ESTABLISHED; receiver.mode=mode; receiver.src_fep=2; receiver.dst_fep=1; receiver.DPDCID=1;
    receiver.start_psn=first; receiver.rx_cur_psn=receiver.cack_psn=receiver.rx_clear_psn=first-1;
    PDStoNET_pkt request{}; request.PDS_type=RUOD_req_header; request.src_fep=1; request.dst_fep=2;
    auto& transport=request.PDS_header.RUOD_req_header;
    transport.type=mode==RUD?RUD_REQ:ROD_REQ; transport.next_hdr=UET_HDR_REQUEST_STD;
    transport.psn=first; transport.spdcid=1; transport.dpdcid=MAX_PDC; transport.clear_psn_off=-1;
    request.SESpkt.bth_type=Standard_Header; auto& header=request.SESpkt.bth_header.Standard_Header;
    header.opcode=2; header.som=header.eom=header.dc=header.rel=1; header.job_id=1;
    header.msg_id=9; header.request_length=1; header.PIDonFEP=header.resource_index=1;
    const auto original=receiver.processRxReq(&request); CHECK(original>UINT32_MAX);
    auto metadata=receiver.rx_pkt_map.at(original);
    receiver.updateRxPsnTracker(&metadata);
    const auto respond=[&](ReceivePacketHandle handle) {
        SES_PDC_rsp response{}; response.rx_pkt_handle=handle; response.gtd_del=true; response.rep_len=21;
        response.pkt.bth_type=Semantic_Response_with_Data_Header;
        auto& data=response.pkt.bth_header.Semantic_Response_with_Data_Header;
        data.opcode=2; data.return_code=1; data.job_id=1; data.read_request_msg_id=9;
        data.response_message_id=17; data.payload_length=data.modified_length=1; response.pkt.payload={42};
        receiver.txRsp(&response);
    };
    respond(original); CHECK(receiver.has_uncached_read(first) && receiver.rx_pkt_map.empty());
    // READ data ACKs may be re-executed instead of cached (§3.5.17). A Clear
    // for the first ACK can race with that second legitimate SES invocation.
    transport.flags.retx=1; CHECK(receiver.reissueReceivedRead(&request) && receiver.rx_req_pkt_q.size()==1);
    const auto duplicate=receiver.rx_req_pkt_q.front(); receiver.rx_req_pkt_q.pop();
    CHECK(duplicate.rx_pkt_handle>original);
    PDStoNET_pkt control{}; control.PDS_type=RUOD_cp_header;
    control.PDS_header.RUOD_cp_header.ctl_type=Clear_cmd; control.PDS_header.RUOD_cp_header.payload=first;
    receiver.rxCtrlClearCmd(&control);
    CHECK(receiver.rx_clear_psn==uint32_t(first-1) && !cleared); // Keep the active duplicate's owner alive.
    respond(duplicate.rx_pkt_handle);
    CHECK(receiver.rx_clear_psn==first && cleared==1 && !receiver.has_uncached_read(first));
    CHECK(receiver.rx_pkt_map.empty()); receiver.freePDC(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (uint32_t first:{0u,UINT32_MAX}) for (bool no_response:{false,true}) {
            clear_waits_for_semantics<I_PDC>(mode,first,no_response); clear_waits_for_semantics<T_PDC>(mode,first,no_response);
        }
        for (auto mode:{RUD,ROD}) for (uint32_t first:{0u,UINT32_MAX}) clear_during_reissued_read(mode,first);
        std::cout<<"PASS20 Clear barriers, valid prefixes/NO_RESPONSE, reissued READ races, response retirement and wrap\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
