#include "Check.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include <iostream>

PDStoNET_pkt acknowledgment(uint32_t explicit_psn,uint32_t cumulative,uint8_t mpr) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_ack_header;
    auto& ack=packet.PDS_header.RUOD_ack_header;
    ack.type=ACK_CC; ack.next_hdr=UET_HDR_RESPONSE;
    ack.ack_psn_off=static_cast<int16_t>(explicit_psn-cumulative); ack.cack_psn=cumulative;
    ack.spdcid=512; ack.dpdcid=1; packet.congestion_ack.mpr=mpr;
    packet.SESpkt.bth_type=Semantic_Response_Header;
    auto& response=packet.SESpkt.bth_header.Semantic_Response_Header;
    response.opcode=0; response.return_code=1; response.message_id=static_cast<uint16_t>(explicit_psn-999);
    return packet;
}

int main() {
    UET::Runtime::EventLoop loop; UET::Runtime::Services services{loop,loop,[]{}};
    services.mpr_zero_override=4;
    services.enable_automatic_window_probes=false; // Inspect only data/retry admission; Probe recovery has its own regression.
    I_PDC sender(&services); CHECK(sender.initPDC(1)); sender.src_fep=1; sender.dst_fep=2;
    PDS_PDC_req request{}; request.next_hdr=UET_HDR_REQUEST_STD; request.delivery_mode=ROD;
    request.som=true; request.eom=true; request.pkt.bth_type=Standard_Header;
    auto& semantic=request.pkt.bth_header.Standard_Header;
    semantic.som=1; semantic.eom=1; semantic.opcode=1; semantic.request_length=1;
    for (unsigned packet=0;packet<8;++packet) { semantic.msg_id=packet+1; sender.sesTxReq(&request); }
    while (!sender.tx_pkt_q.empty()) sender.tx_pkt_q.pop(); sender.gen_cm=NONE;
    auto first=acknowledgment(1000,1000,0); sender.rxAck(&first);
    CHECK(sender.MPR==Default_MPR); // A received peer limit must not resize local receive resources.
    CHECK(sender.unack_cnt==7);
    const auto active_timers=sender.rto_timer_.getActiveTimerCount();
    sender.txRto(1007);
    CHECK(sender.tx_pkt_map.at(1007).retry_cnt==0 && sender.tx_pkt_q.empty());
    CHECK(sender.rto_timer_.getActiveTimerCount()==active_timers-1);
    sender.txRto(1004); // CACK+range is inclusive.
    CHECK(sender.tx_pkt_map.at(1004).retry_cnt==1 && sender.tx_pkt_q.size()==1);
    sender.tx_pkt_q.pop(); sender.tx_req_q.push(request); sender.gen_cm=NONE;
    CHECK(!sender.hasPendingWork()); // Neither a new PSN nor the deferred retry is admissible.
    auto impossible=acknowledgment(2000,2000,255); sender.rxAck(&impossible); sender.gen_cm=NONE;
    CHECK(!sender.hasPendingWork()); // An unsent future CACK cannot open the peer range.
    auto invalid_explicit=acknowledgment(2000,1001,255); sender.rxAck(&invalid_explicit); sender.gen_cm=NONE;
    CHECK(!sender.hasPendingWork() && sender.unack_cnt==7); // Plausible CACK cannot rescue an out-of-range ACK_PSN.
    auto progress=acknowledgment(1004,1004,0); sender.rxAck(&progress); sender.gen_cm=NONE;
    CHECK(sender.hasPendingWork()); sender.openChk(); // Deferred retry precedes new data.
    CHECK(sender.tx_pkt_map.at(1007).retry_cnt==1 && sender.tx_pkt_q.size()==1);
    CHECK(sender.tx_pkt_q.front().PDS_header.RUOD_req_header.psn==1007);
    sender.tx_pkt_q.pop(); sender.gen_cm=NONE; sender.openChk();
    CHECK(sender.tx_pkt_q.size()==1 && sender.tx_pkt_q.front().PDS_header.RUOD_req_header.psn==1008);
    sender.tx_pkt_q.pop(); sender.tx_req_q.push(request); sender.gen_cm=NONE;
    auto stale_resize=acknowledgment(1005,1004,255); sender.rxAck(&stale_resize); sender.gen_cm=NONE;
    CHECK(sender.clear_psn==1005 && !sender.hasPendingWork());
    auto obsolete=acknowledgment(1003,1005,255); sender.rxAck(&obsolete); sender.gen_cm=NONE;
    CHECK(!sender.hasPendingWork()); // ACK_PSN below the prior peer CACK must not update MPR or CACK.
    // Selective progress changes the local clear tracker, but only peer CACK
    // can advance the advertised range's anchor. A same-CACK resize is stale.
    auto newer=acknowledgment(1005,1005,0); sender.rxAck(&newer); sender.gen_cm=NONE;
    CHECK(sender.hasPendingWork()); sender.openChk();
    CHECK(sender.tx_pkt_q.size()==1 && sender.tx_pkt_q.front().PDS_header.RUOD_req_header.psn==1009);
    CHECK(sender.MPR==Default_MPR);
    sender.freePDC(); CHECK(loop.pending()==0);
    std::cout<<"PASS original PDS peer-range admission, delayed retransmit timers and independent receive capacity\n";
}
