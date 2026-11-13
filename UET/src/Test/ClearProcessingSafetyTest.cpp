#include "Check.hpp"
#include "../Runtime/Runtime.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include <iostream>
#include <type_traits>
using namespace UET::Runtime;

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
    const auto respond=[&](uint16_t handle,bool guaranteed,bool no_response=false) {
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
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (uint32_t first:{0u,UINT32_MAX}) for (bool no_response:{false,true}) {
            clear_waits_for_semantics<I_PDC>(mode,first,no_response); clear_waits_for_semantics<T_PDC>(mode,first,no_response);
        }
        std::cout<<"PASS16 I/T PDC Clear barriers, valid prefixes/NO_RESPONSE, response cache retirement and sequence wrap\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
