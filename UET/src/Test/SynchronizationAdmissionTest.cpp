#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include "../PDS/DefaultSemanticResponse.hpp"
#include <iostream>
#include <type_traits>
using namespace UET::Runtime;

SEStoPDS_pkt synchronized_packet(bool atomic=false) {
    SEStoPDS_pkt packet{}; packet.bth_type=Standard_Header;
    packet.eth_type=atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header;
    auto& header=packet.bth_header.Standard_Header;
    header.opcode=atomic?0x11:0x10; header.som=header.eom=header.dc=header.rel=1; header.hd=!atomic;
    header.msg_id=9; header.job_id=header.PIDonFEP=header.resource_index=1; header.request_length=4;
    auto& synchronization=atomic?packet.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
        packet.eth_header.Synchronized_Operation_Extension_Header;
    synchronization.sync_group=0xabcd; synchronization.sync_count=1;
    if (atomic) packet.eth_header.Synchronized_Atomic_Extension_Headers.atomic.atomic_datatype=5;
    packet.payload={1,2,3,4}; return packet;
}
void check_metadata(const PDC_SES_req& request,bool atomic) {
    CHECK(request.rx_pkt_handle==UET::Runtime::kInvalidReceivePacketHandle && request.pkt.payload.empty());
    CHECK(request.pkt.eth_type==(atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header));
    const auto& synchronization=atomic?request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
        request.pkt.eth_header.Synchronized_Operation_Extension_Header;
    CHECK(synchronization.sync_group==0xabcd && synchronization.sync_count==1);
}
template<class Receiver> void established_refusal(pdc_mode mode,bool atomic) {
    EventLoop loop; Services services{loop,loop,[] {}}; Receiver receiver(&services);
    const bool initiator=std::is_same_v<Receiver,I_PDC>;
    const uint16_t local=initiator?1:MAX_PDC,remote=initiator?MAX_PDC:1;
    CHECK(receiver.initPDC(local)); receiver.state=ESTABLISHED; receiver.mode=mode; receiver.DPDCID=remote;
    receiver.SYN=0; receiver.start_psn=1000; receiver.rx_cur_psn=receiver.cack_psn=receiver.rx_clear_psn=999;
    receiver.src_fep=initiator?1:2; receiver.dst_fep=initiator?2:1;
    bool available=false; size_t reservations=0;
    services.semantic_admission=[&](const PDC_SES_req& request) {
        check_metadata(request,atomic); ++reservations;
        return available?SemanticAdmission::ReservedMessage:SemanticAdmission::NoSynchronizationState;
    };
    PDStoNET_pkt packet{}; packet.src_fep=receiver.dst_fep; packet.dst_fep=receiver.src_fep; packet.PDS_type=RUOD_req_header;
    auto& transport=packet.PDS_header.RUOD_req_header;
    transport.type=mode==RUD?RUD_REQ:ROD_REQ; transport.next_hdr=UET_HDR_REQUEST_STD;
    transport.psn=1000; transport.clear_psn_off=-1; transport.spdcid=remote; transport.dpdcid=local;
    transport.flags.ar=transport.flags.retx=1; packet.SESpkt=synchronized_packet(atomic);
    receiver.rxReq(&packet);
    CHECK(reservations==1 && receiver.rx_pkt_map.empty() && receiver.rx_req_pkt_q.empty() &&
        receiver.rx_cur_psn==999 && receiver.cack_psn==999 && receiver.tx_ack_buffer.empty());
    CHECK(receiver.tx_pkt_q.size()==1); const auto refused=receiver.tx_pkt_q.front(); receiver.tx_pkt_q.pop();
    CHECK(refused.PDS_type==nack_header && refused.PDS_header.nack_header.nack_code==UET_NO_SES_SYNC_AVAIL &&
        refused.PDS_header.nack_header.spdcid==local);
    available=true; receiver.rxReq(&packet); receiver.rxReq(&packet);
    CHECK(reservations==2 && receiver.rx_req_pkt_q.size()==1 && receiver.rx_pkt_map.size()==1);
    CHECK(receiver.rx_req_pkt_q.front().pkt.payload==packet.SESpkt.payload);
    receiver.freePDC(); CHECK(!loop.pending());
}
void real_pds_recovery(bool preopened,pdc_mode mode,bool congestion,bool atomic) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,forward),target(2,loop,trace,reverse);
    source.configure_semantic_payload_mtu(64); target.configure_semantic_payload_mtu(64);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,128);
        source.enable_nscc(config); target.enable_nscc(config);
    }
    bool available=false; size_t received=0,completed=0,refusals=0,without_context=0;
    target.set_receive_admission([&](const PDC_SES_req& request) {
        check_metadata(request,atomic);
        return available?SemanticAdmission::ReservedMessage:SemanticAdmission::NoSynchronizationState;
    },[](const PDC_SES_req&) {});
    target.set_request_handler([&](const PDC_SES_req& request) {
        CHECK(available && request.pkt.payload==std::vector<uint8_t>({1,2,3,4})); ++received;
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.rsp_len=12; response.gtd_del=true; response.rsp=UET::PDS::default_semantic_response(request.pkt);
        CHECK(target.manager().pushSESResponse(response)); target.wake();
    });
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_header.Semantic_Response_Header.return_code==1); ++completed;
    });
    fabric.set_capture([&](Time,const Frame& frame) {
        if (frame.source!=2) return;
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==nack_header) {
            CHECK(packet.PDS_header.nack_header.nack_code==UET_NO_SES_SYNC_AVAIL);
            ++refusals; without_context+=packet.PDS_header.nack_header.spdcid==0;
        }
    });
    if (preopened) { CHECK(source.open_connection(2,1,mode)!=UINT16_MAX); loop.run_until(100000); }
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt=synchronized_packet(atomic); request.pkt_len=atomic?56:52;
    CHECK(source.submit(request)); loop.run_until(kMillisecond);
    CHECK(!received && !completed && refusals && (without_context>0)==!preopened);
    CHECK(target.manager().getPDSStatus().open_cnt==(preopened?1:0));
    available=true; loop.run(100000);
    CHECK(received==1 && completed==1);
    source.close(); target.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (bool atomic:{false,true}) {
            established_refusal<I_PDC>(mode,atomic); established_refusal<T_PDC>(mode,atomic);
            for (bool preopened:{false,true}) for (bool congestion:{false,true}) real_pds_recovery(preopened,mode,congestion,atomic);
        }
        std::cout<<"PASS synchronized-state NACK at allocated/unallocated PDCs, header-only admission, unchanged PSN and real recovery\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
