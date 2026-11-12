#include "Check.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include <iostream>

int main() {
    try {
        UET::Runtime::EventLoop loop;
        UET::Runtime::Services services{loop,loop,[]{}};
        // This unit exercises the transport tracker directly. SES result
        // validation is covered through rxAck in SelectiveAcknowledgmentTest.
        services.standard_wire=false;
        I_PDC sender(&services); CHECK(sender.initPDC(1));
        sender.start_psn=UINT32_MAX-1; sender.tx_cur_psn=sender.start_psn;
        sender.clear_psn=sender.start_psn-1;
        PDS_PDC_req request{}; request.next_hdr=UET_HDR_REQUEST_STD;
        request.som=true; request.eom=true;
        request.pkt.bth_type=Standard_Header;
        request.pkt.bth_header.Standard_Header.som=1;
        request.pkt.bth_header.Standard_Header.eom=1;
        sender.sesTxReq(&request); sender.sesTxReq(&request); sender.sesTxReq(&request);
        CHECK(sender.unack_cnt==3); CHECK(sender.rto_timer_.getActiveTimerCount()==3);
        sender.updateTxPsnTracker(0,0,UINT32_MAX-2); // Last PSN ACKed first, across wrap.
        CHECK(sender.unack_cnt==2); CHECK(sender.clear_psn==UINT32_MAX-2);
        CHECK(sender.rto_timer_.getActiveTimerCount()==2);
        sender.updateTxPsnTracker(0,0,UINT32_MAX-2);
        CHECK(sender.unack_cnt==2); // Duplicate ACK has no side effects.
        sender.updateTxPsnTracker(1234,0,1234);
        CHECK(sender.unack_cnt==2); // Unsent PSNs cannot acknowledge buffers.
        sender.updateTxPsnTracker(UINT32_MAX-1,0,UINT32_MAX-2);
        CHECK(sender.clear_psn==UINT32_MAX-1); CHECK(sender.unack_cnt==1);
        sender.updateTxPsnTracker(UINT32_MAX,0,UINT32_MAX-2);
        CHECK(sender.clear_psn==0); CHECK(sender.unack_cnt==0);
        CHECK(sender.tx_pkt_buffer.empty()); CHECK(sender.tx_pkt_map.empty());
        CHECK(sender.rto_timer_.getActiveTimerCount()==0); CHECK(loop.pending()==0);
        sender.txRto(UINT32_MAX); // Expired-but-already-ACKed queue entry is stale.
        sender.reTx(UINT32_MAX); // A late explicit retry is harmless too.
        while (!sender.tx_pkt_q.empty()) sender.tx_pkt_q.pop();
        PDStoNET_pkt control{}; control.PDS_type=RUOD_cp_header;
        control.PDS_header.RUOD_cp_header.type=CP;
        control.PDS_header.RUOD_cp_header.ctl_type=Close_cmd;
        control.PDS_header.RUOD_cp_header.psn=11;
        sender.tx_pkt_buffer.emplace(11,control);
        sender.reTx(11);
        CHECK(sender.tx_pkt_q.size()==1);
        CHECK(sender.tx_pkt_q.front().PDS_header.RUOD_cp_header.flags.retx==1);
        CHECK(sender.tx_pkt_q.front().PDS_header.RUOD_cp_header.ctl_type==Close_cmd);

        I_PDC window_sender(&services); CHECK(window_sender.initPDC(2));
        for (size_t packet=0;packet<Default_MPR;++packet) window_sender.sesTxReq(&request);
        CHECK(window_sender.pause_pdc);
        for (uint32_t sequence=1001;sequence<1000+Default_MPR;++sequence)
            window_sender.updateTxPsnTracker(sequence,0,999);
        CHECK(window_sender.unack_cnt==1);
        CHECK(window_sender.pause_pdc); // One hole still pins the PSN window.
        window_sender.updateTxPsnTracker(1000,0,999);
        CHECK(!window_sender.pause_pdc && window_sender.unack_cnt==0);
        CHECK(loop.pending()==0);
        std::cout << "PASS: selective and duplicate ACKs, inclusive cleanup, PSN wrap and stale RTO\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
