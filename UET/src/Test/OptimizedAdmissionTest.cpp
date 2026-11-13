#include "Check.hpp"
#include "../Runtime/Runtime.hpp"
#include "../PDS/PDS_Manager/PDSManager.hpp"
#include <iostream>
using namespace UET::Runtime;

// Wire support must not silently reinterpret a no-MID optimized request as a
// Standard_Header before its distinct SES/PDS ownership path is implemented.
int main() {
    try {
        size_t cases=0;
        for (bool ordered:{false,true}) for (auto format:{Optimized_Header,Small_Message_RMA_Header,Optimized_Response_with_Data_Header}) {
            EventLoop loop; size_t admissions=0,events=0;
            Services services{loop,loop,[] {}};
            services.semantic_admission=[&](const PDC_SES_req&) { ++admissions; return SemanticAdmission::ReservedPacket; };
            services.pdc_event=[&](const PdcEvent&) { ++events; };
            {
                PDS_Manager manager(&services); CHECK(manager.initPDSM());
                PDStoNET_pkt packet{}; packet.src_fep=1; packet.dst_fep=2; packet.SESpkt.bth_type=format;
                if (format==Optimized_Response_with_Data_Header) {
                    packet.PDS_type=RUOD_ack_header; packet.PDS_header.RUOD_ack_header.type=ACK;
                    packet.PDS_header.RUOD_ack_header.next_hdr=UET_HDR_RESPONSE_DATA_SMALL;
                } else {
                    packet.PDS_type=RUOD_req_header; auto& header=packet.PDS_header.RUOD_req_header;
                    header.type=ordered?ROD_REQ:RUD_REQ; header.flags.syn=1; header.spdcid=17;
                    header.next_hdr=format==Optimized_Header?UET_HDR_REQUEST_SMALL:UET_HDR_REQUEST_MEDIUM;
                    if (format==Optimized_Header) {
                        auto& semantic=packet.SESpkt.bth_header.Optimized_Header;
                        semantic.opcode=1; semantic.som=semantic.eom=semantic.rel=1; semantic.job_id=1;
                    } else {
                        auto& semantic=packet.SESpkt.bth_header.Small_Message_RMA_Header;
                        semantic.opcode=1; semantic.som=semantic.eom=semantic.rel=1; semantic.job_id=1;
                    }
                }
                CHECK(manager.Net_rx_pkt_q.push(packet)); manager.rxPkt();
                CHECK(!manager.open_cnt && !admissions && !events && manager.PDStoNet.empty() &&
                    manager.PDCtoSES_req.empty() && manager.PDCtoSES_rsp.empty());
            }
            CHECK(!loop.pending()); ++cases;
        }
        CHECK(cases==6); std::cout<<"PASS6 optimized wire-only ingress leaves PDC, SES, timers and peer identities untouched\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
