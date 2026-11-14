#include "Check.hpp"
#include "../PDS/PDS_Manager/PDSManager.hpp"
#include <iostream>
#include <set>

int main() {
    try {
        UET::Runtime::EventLoop loop;
        UET::Runtime::Services services{loop,loop,[]{}};
        PDS_Manager manager(&services); CHECK(manager.initPDSM());
        CHECK(!manager.allocPDC(0,1,99)); // Reserved on the wire, not an allocatable initiator ID.
        CHECK(manager.allocPDC(MAX_PDC,1,99)); // First target ID, not an initiator.
        CHECK(manager.TPDC_Processmanager.getActiveProcessCount()==1);
        CHECK(manager.assignPDC(1,MAX_PDC));
        CHECK(manager.BitMap[MAX_PDC]==1);
        CHECK(!manager.assignPDC(1,UINT16_MAX)); CHECK(!manager.allocPDC(UINT16_MAX,1,99));
        std::set<uint16_t> targets{MAX_PDC};
        for (uint32_t peer=1;peer<=64;++peer) {
            const auto id=manager.muxRx2PDCID(peer,99,7);
            CHECK(id>=MAX_PDC && id<MAX_PDC*2);
            CHECK(targets.insert(id).second);
            CHECK(manager.allocPDC(id,peer,99));
            CHECK(manager.muxRx2PDCID(peer,99,7)==id);
            CHECK(manager.assignPDC(1,id));
        }
        std::set<int> initiators;
        for (uint32_t peer=1;peer<=64;++peer) {
            const auto id=manager.muxTx2PDCID(1,peer,0,ROD);
            CHECK(id>0 && id<MAX_PDC); CHECK(initiators.insert(id).second);
            CHECK(manager.allocPDC(id,peer,99));
            for (size_t repeat=0;repeat<20;++repeat) CHECK(manager.muxTx2PDCID(1,peer,0,ROD)==id);
        }
        PDStoNET_pkt bad{}; bad.PDS_type=RUOD_ack_header;
        bad.PDS_header.RUOD_ack_header.dpdcid=UINT16_MAX;
        CHECK(manager.Net_rx_pkt_q.push(bad)); manager.mainChk();
        CHECK(manager.PDC_close_q.push(MAX_PDC)); manager.mainChk();
        CHECK(manager.TPDC_Processmanager.getActiveProcessCount()==64);
        PDStoNET_pkt zero_source{}; zero_source.PDS_type=RUOD_req_header;
        zero_source.src_fep=1000; zero_source.dst_fep=99;
        auto& startup=zero_source.PDS_header.RUOD_req_header;
        startup.type=ROD_REQ; startup.next_hdr=UET_HDR_NONE; startup.flags.syn=1; startup.psn=1000;
        CHECK(manager.Net_rx_pkt_q.push(zero_source)); manager.mainChk();
        PDStoNET_pkt rejected{}; CHECK(manager.PDStoNet.pop(rejected));
        CHECK(rejected.PDS_type==nack_header && rejected.PDS_header.nack_header.nack_code==UET_PDC_HDR_MISMATCH);
        CHECK(manager.TPDC_Processmanager.getActiveProcessCount()==64);
        CHECK(loop.pending()==0);
        std::cout<<"PASS: both PDC ID spaces, collision-safe reuse, first target boundary and invalid wire ID rejection\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
