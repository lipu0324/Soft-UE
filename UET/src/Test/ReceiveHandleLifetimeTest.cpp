#include "Check.hpp"
#include "../Runtime/Runtime.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include <iostream>
using namespace UET::Runtime;

class ReceiveReplayProbe final : public T_PDC {
public:
    using T_PDC::T_PDC;
    using PDC::reissueReceivedRead;
    bool has_uncached_read(uint32_t sequence) const { return uncached_read_responses_.count(sequence); }
};

static void replay_cannot_adopt_old_semantic_response(pdc_mode mode,uint32_t first) {
    EventLoop loop; Services services{loop,loop,[] {}};
    ReceiveReplayProbe receiver(&services); CHECK(receiver.initPDC(MAX_PDC));
    receiver.state=ESTABLISHED; receiver.mode=mode; receiver.src_fep=2; receiver.dst_fep=1; receiver.DPDCID=1;
    receiver.start_psn=first; receiver.rx_cur_psn=receiver.cack_psn=receiver.rx_clear_psn=first-1;
    PDStoNET_pkt request{}; request.PDS_type=RUOD_req_header; request.src_fep=1; request.dst_fep=2;
    auto& transport=request.PDS_header.RUOD_req_header;
    transport.type=mode==RUD?RUD_REQ:ROD_REQ; transport.next_hdr=UET_HDR_REQUEST_STD;
    transport.psn=first; transport.spdcid=1; transport.dpdcid=MAX_PDC; transport.clear_psn_off=-1;
    request.SESpkt.bth_type=Standard_Header; auto& header=request.SESpkt.bth_header.Standard_Header;
    header.opcode=2; header.som=header.eom=header.dc=header.rel=1; header.job_id=1;
    header.msg_id=9; header.request_length=1; header.PIDonFEP=header.resource_index=1;
    const auto original=receiver.processRxReq(&request); auto metadata=receiver.rx_pkt_map.at(original);
    receiver.updateRxPsnTracker(&metadata);
    SES_PDC_rsp response{}; response.rx_pkt_handle=original; response.gtd_del=true; response.rep_len=21;
    response.pkt.bth_type=Semantic_Response_with_Data_Header;
    auto& data=response.pkt.bth_header.Semantic_Response_with_Data_Header;
    data.opcode=2; data.return_code=1; data.job_id=1; data.read_request_msg_id=9;
    data.response_message_id=17; data.payload_length=data.modified_length=1; response.pkt.payload={42};
    receiver.txRsp(&response); CHECK(receiver.has_uncached_read(first) && receiver.rx_pkt_map.empty());
    transport.flags.retx=1; CHECK(receiver.reissueReceivedRead(&request) && receiver.rx_req_pkt_q.size()==1);
    const auto replay=receiver.rx_req_pkt_q.front(); receiver.rx_req_pkt_q.pop();
    // The same PSN can legitimately execute READ again (§3.5.17). A delayed
    // duplicate SES callback from its first execution must not consume this
    // new execution's RX handle, even on the same PDC and connection epoch.
    receiver.txRsp(&response);
    if (!receiver.rx_pkt_map.count(replay.rx_pkt_handle))
        throw std::runtime_error("old semantic READ response consumed a new reexecution's RX handle");
    CHECK(original!=replay.rx_pkt_handle);
    response.rx_pkt_handle=replay.rx_pkt_handle; receiver.txRsp(&response); CHECK(receiver.rx_pkt_map.empty());
    receiver.freePDC(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (uint32_t first:{0u,UINT32_MAX}) replay_cannot_adopt_old_semantic_response(mode,first);
        std::cout<<"PASS4 semantic receive handles distinguish repeated execution of an identical READ PSN\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
