#include "Check.hpp"
#include "../Runtime/Runtime.hpp"
#include "../PDS/PDS_Manager/PDSManager.hpp"
#include <iostream>
using namespace UET::Runtime;

// No-MID requests use an explicit field projection before admission. Resource
// refusal must preserve their packet identity without allocating a PDC.
int main() {
    try {
        size_t cases=0;
        for (bool ordered:{false,true}) for (auto format:{Optimized_Header,Small_Message_RMA_Header,Optimized_Response_with_Data_Header}) {
            EventLoop loop; size_t admissions=0,events=0;
            Services services{loop,loop,[] {}};
            services.semantic_admission=[&](const PDC_SES_req& request) {
                CHECK(request.pkt.bth_type==Standard_Header && request.request_wire_format==format &&
                    !request.pkt.bth_header.Standard_Header.msg_id && request.pkt.bth_header.Standard_Header.job_id==1);
                ++admissions; return SemanticAdmission::Rejected;
            };
            services.pdc_event=[&](const PdcEvent&) { ++events; };
            {
                PDS_Manager manager(&services); CHECK(manager.initPDSM());
                PDStoNET_pkt packet{}; packet.src_fep=1; packet.dst_fep=2; packet.SESpkt.bth_type=format;
                if (format==Optimized_Response_with_Data_Header) {
                    packet.PDS_type=RUDI_header; packet.PDS_header.RUDI_header.type=RUDI_RESP;
                    packet.PDS_header.RUDI_header.next_hdr=UET_HDR_RESPONSE_DATA_SMALL;
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
                CHECK(!manager.open_cnt && !events && manager.PDCtoSES_req.empty() && manager.PDCtoSES_rsp.empty());
                if (format==Optimized_Response_with_Data_Header) CHECK(!admissions && manager.PDStoNet.empty());
                else {
                    PDStoNET_pkt refusal{}; CHECK(admissions==1 && manager.PDStoNet.pop(refusal));
                    CHECK(refusal.PDS_type==nack_header && refusal.PDS_header.nack_header.nack_code==UET_NO_SES_MSG_AVAIL &&
                        !refusal.PDS_header.nack_header.spdcid && refusal.PDS_header.nack_header.dpdcid==17);
                }
            }
            CHECK(!loop.pending()); ++cases;
        }
        CHECK(cases==6); std::cout<<"PASS6 canonical no-MID admission/resource refusal and unsupported optimized data-response fencing\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
