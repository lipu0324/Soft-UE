#include "Check.hpp"
#include "../Runtime/Runtime.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include <iostream>
using namespace UET::Runtime;

class ReceiveHandleProbe final : public T_PDC {
public:
    using T_PDC::T_PDC;
    using PDC::admitSemanticRequest;
};
static PDStoNET_pkt no_op(pdc_mode mode,uint32_t sequence) {
    PDStoNET_pkt request{}; request.PDS_type=RUOD_req_header; request.src_fep=1; request.dst_fep=2;
    auto& transport=request.PDS_header.RUOD_req_header;
    transport.type=mode==RUD?RUD_REQ:ROD_REQ; transport.next_hdr=UET_HDR_REQUEST_STD;
    transport.psn=sequence; transport.spdcid=1; transport.dpdcid=MAX_PDC; transport.clear_psn_off=-1;
    request.SESpkt.bth_type=Standard_Header;
    auto& header=request.SESpkt.bth_header.Standard_Header;
    header.som=header.eom=header.dc=header.rel=1; header.job_id=header.msg_id=1;
    header.PIDonFEP=header.resource_index=1;
    return request;
}
static void establish(ReceiveHandleProbe& receiver,pdc_mode mode,uint32_t sequence) {
    CHECK(receiver.initPDC(MAX_PDC));
    receiver.state=ESTABLISHED; receiver.mode=mode; receiver.src_fep=2; receiver.dst_fep=1; receiver.DPDCID=1;
    receiver.start_psn=sequence; receiver.rx_cur_psn=receiver.cack_psn=receiver.rx_clear_psn=sequence-1;
}
static void wide_handle_survives_pdc_replacement(pdc_mode mode,uint32_t first) {
    EventLoop loop; Services services{loop,loop,[] {}};
    services.receive_handle_allocator=ReceiveHandleAllocator(uint64_t{1}<<32);
    ReceiveHandleProbe previous(&services); establish(previous,mode,first);
    auto packet=no_op(mode,first); const auto old_handle=previous.processRxReq(&packet);
    previous.freePDC();
    ReceiveHandleProbe replacement(&services); establish(replacement,mode,first+65536u);
    packet.PDS_header.RUOD_req_header.psn=first+65536u;
    const auto new_handle=replacement.processRxReq(&packet); auto metadata=replacement.rx_pkt_map.at(new_handle);
    replacement.updateRxPsnTracker(&metadata); replacement.fwdReq2SES(new_handle,metadata,&packet.SESpkt);
    const auto request=replacement.rx_req_pkt_q.front(); replacement.rx_req_pkt_q.pop();
    CHECK(old_handle>UINT16_MAX && new_handle>old_handle && replacement.ownsReceiveExecution(request));
    auto wrong=request; wrong.rx_pkt_handle=old_handle; CHECK(!replacement.ownsReceiveExecution(wrong));
    wrong=request; ++wrong.connection_start_psn; CHECK(!replacement.ownsReceiveExecution(wrong));
    wrong=request; ++wrong.source_fep; CHECK(!replacement.ownsReceiveExecution(wrong));
    wrong=request; ++wrong.orig_psn; CHECK(!replacement.ownsReceiveExecution(wrong));
    SES_PDC_rsp response{}; response.rx_pkt_handle=old_handle; response.rep_len=12;
    response.pkt.bth_type=Semantic_Response_Header;
    auto& semantic=response.pkt.bth_header.Semantic_Response_Header;
    semantic.return_code=semantic.job_id=semantic.message_id=1;
    replacement.txRsp(&response);
    CHECK(replacement.rx_pkt_map.count(new_handle) && replacement.tx_pkt_q.empty());
    response.rx_pkt_handle=new_handle; replacement.txRsp(&response); CHECK(replacement.rx_pkt_map.empty());
    CHECK(!replacement.ownsReceiveExecution(request)); replacement.freePDC(); CHECK(!loop.pending());
}
static void exhaustion_precedes_semantic_admission(pdc_mode mode) {
    EventLoop loop; Services services{loop,loop,[] {}}; size_t reservations=0;
    services.receive_handle_allocator=ReceiveHandleAllocator(kInvalidReceivePacketHandle-1);
    services.semantic_admission=[&](const PDC_SES_req&) { ++reservations; return SemanticAdmission::ReservedMessage; };
    ReceiveHandleProbe receiver(&services); establish(receiver,mode,0);
    auto request=no_op(mode,0); const auto handle=receiver.processRxReq(&request);
    CHECK(handle==kInvalidReceivePacketHandle-1); request.PDS_header.RUOD_req_header.psn=1;
    CHECK(!receiver.admitSemanticRequest(request) && !reservations && receiver.rx_pkt_map.size()==1);
    CHECK(receiver.tx_pkt_q.size()==1); const auto nack=receiver.tx_pkt_q.front(); receiver.tx_pkt_q.pop();
    CHECK(nack.PDS_type==nack_header && nack.PDS_header.nack_header.nack_code==UET_NO_PKT_BUFFER);
    check_throws<std::overflow_error>([&] { receiver.processRxReq(&request); });
    CHECK(receiver.rx_pkt_map.size()==1 && receiver.rx_pkt_map.count(handle));
    receiver.freePDC(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) {
            for (uint32_t first:{0u,UINT32_MAX}) wide_handle_survives_pdc_replacement(mode,first);
            exhaustion_precedes_semantic_admission(mode);
        }
        std::cout<<"PASS6 wide RX identities, PDC reuse, exact ownership and pre-admission exhaustion\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
