#include "Check.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include <iostream>

using namespace UET::Runtime;
using UET::PDS::PsnRangeConfiguration;

class InspectableSource : public I_PDC {
public:
    using I_PDC::I_PDC;
    using PDC::peerWindowAllows;
};
class InspectableTarget : public T_PDC {
public:
    using T_PDC::T_PDC;
    void accept_initial_noop(uint32_t initial_sequence) {
        PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
        auto& control=packet.PDS_header.RUOD_cp_header;
        control.type=CP; control.ctl_type=Noop; control.flags.syn=control.flags.ar=1;
        control.spdcid=1; control.psn=initial_sequence;
        netRxCm(&packet); CHECK(state==ESTABLISHED);
    }
};

void all_default_encodings(uint32_t initial_sequence) {
    for (uint32_t encoding=0;encoding<=255;++encoding) {
        EventLoop loop; Services services{loop,loop,[]{}};
        services.psn_ranges.default_mpr=encoding;
        services.psn_ranges.local_packet_capacity=3;
        InspectableSource source(&services); CHECK(source.initPDC(1,initial_sequence));
        const uint32_t range=std::max(1u,encoding)*128;
        CHECK(source.local_packet_capacity==3);
        if (range>=4096) {
            source.SYN=true;
            CHECK(source.peerWindowAllows(initial_sequence+4095));
            CHECK(!source.peerWindowAllows(initial_sequence+4096)); // SYN offset is only 12 bits.
            source.SYN=false;
        }
        CHECK(source.peerWindowAllows(initial_sequence+range-1));
        CHECK(!source.peerWindowAllows(initial_sequence+range));
        PDStoNET_pkt unsolicited{}; unsolicited.PDS_type=RUOD_ack_header;
        auto& ack=unsolicited.PDS_header.RUOD_ack_header;
        ack.type=ACK_CC; ack.next_hdr=UET_HDR_NONE; ack.cack_psn=initial_sequence-1;
        ack.spdcid=512; ack.dpdcid=1; unsolicited.congestion_ack.mpr=255;
        source.rxAck(&unsolicited); // A configured initial window cannot authorize an ACK for unsent data.
        CHECK(!source.peerWindowAllows(initial_sequence+range));
        // Settings belong to a PDC incarnation, not to mutable host defaults.
        services.psn_ranges.default_mpr=1;
        CHECK(source.peerWindowAllows(initial_sequence+range-1));
        services.psn_ranges.default_mpr=encoding;
        InspectableTarget target(&services); CHECK(target.initPDC(512));
        target.accept_initial_noop(initial_sequence);
        CHECK(target.tx_pkt_q.size()==1);
        CHECK(target.tx_pkt_q.front().PDS_header.RUOD_ack_header.type==ACK_CC);
        CHECK(target.tx_pkt_q.front().congestion_ack.mpr==std::max(1u,encoding));
        source.freePDC(); target.freePDC(); CHECK(loop.pending()==0);
    }
}

PDStoNET_pkt data_packet(uint32_t sequence,bool retransmitted=false) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
    auto& header=packet.PDS_header.RUOD_req_header;
    header.type=RUD_REQ; header.psn=sequence; header.flags.retx=retransmitted;
    return packet;
}
PDStoNET_pkt control_packet(uint32_t sequence) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
    auto& header=packet.PDS_header.RUOD_cp_header;
    header.type=CP; header.ctl_type=Noop; header.flags.ar=1;
    header.psn=sequence; header.spdcid=1; header.dpdcid=512;
    return packet;
}

void initial_reduced_receive_window(uint32_t initial_sequence) {
    EventLoop loop; Services services{loop,loop,[]{}};
    services.psn_ranges.advertised_mpr=1; // Initial default8, current receive range128.
    InspectableTarget target(&services); CHECK(target.initPDC(512));
    auto request=data_packet(initial_sequence+128);
    auto& header=request.PDS_header.RUOD_req_header;
    header.flags.syn=1; header.spdcid=1; header.psn_off=128;
    header.next_hdr=UET_HDR_REQUEST_STD; request.SESpkt.bth_type=Standard_Header;
    target.netRxReq(&request);
    CHECK(target.state==ESTABLISHED && target.tx_pkt_q.empty() && target.rx_req_pkt_q.empty());
    auto recovery=control_packet(initial_sequence); target.netRxCm(&recovery);
    CHECK(target.tx_pkt_q.size()==1 && target.tx_pkt_q.front().PDS_type==RUOD_ack_header);
    CHECK(target.tx_pkt_q.front().congestion_ack.mpr==1);
    target.freePDC(); CHECK(loop.pending()==0);
}

void cack_receive_boundary(uint32_t initial_sequence) {
    EventLoop loop; Services services{loop,loop,[]{}};
    services.psn_ranges.default_mpr=1; services.psn_ranges.local_packet_capacity=3;
    InspectableTarget target(&services); CHECK(target.initPDC(512));
    target.accept_initial_noop(initial_sequence); target.tx_pkt_q.pop();
    auto last=data_packet(initial_sequence+128); target.chkRxError(&last); CHECK(target.error_chk==OPEN);
    auto outside=data_packet(initial_sequence+129); target.chkRxError(&outside); CHECK(target.error_chk==DROP);
    // Contiguous reception can advance while a guaranteed response pins CACK.
    // The resource window must remain anchored at CACK, not rx_cur_psn.
    target.rx_cur_psn=initial_sequence+200;
    target.chkRxError(&outside); CHECK(target.error_chk==DROP);
    target.cack_psn=initial_sequence+200;
    auto retained=data_packet(initial_sequence+1,true);
    target.chkRxError(&retained); CHECK(target.error_chk==ACK_ERROR); // Clear..CACK replay exception.
    target.rx_clear_psn=initial_sequence+1;
    target.chkRxError(&retained); CHECK(target.error_chk==DROP);

    target.freePDC(); CHECK(target.initPDC(512));
    target.accept_initial_noop(initial_sequence); target.tx_pkt_q.pop();
    auto control=control_packet(initial_sequence+128); target.netRxCm(&control);
    CHECK(target.tx_pkt_q.size()==1 && target.tx_pkt_q.front().congestion_ack.mpr==1);
    target.tx_pkt_q.pop(); control=control_packet(initial_sequence+129); target.netRxCm(&control);
    CHECK(target.tx_pkt_q.empty());
    control.PDS_header.RUOD_cp_header.ctl_type=Probe;
    control.PDS_header.RUOD_cp_header.psn=0; target.netRxCm(&control);
    CHECK(target.tx_pkt_q.size()==1 && target.tx_pkt_q.front().congestion_ack.mpr==1);
    target.freePDC(); CHECK(loop.pending()==0);
}

void initial_source_admission(uint32_t initial_sequence) {
    EventLoop loop; Services services{loop,loop,[]{}};
    services.psn_ranges.default_mpr=1; services.psn_ranges.local_packet_capacity=256;
    InspectableSource source(&services); CHECK(source.initPDC(1,initial_sequence));
    source.setFep(2,1); source.bindCongestionContext(RUD);
    PDS_PDC_req request{}; request.delivery_mode=RUD; request.next_hdr=UET_HDR_REQUEST_STD;
    request.som=request.eom=true; request.pkt.bth_type=Standard_Header;
    auto& semantic=request.pkt.bth_header.Standard_Header;
    semantic.opcode=0; semantic.som=semantic.eom=semantic.dc=1; semantic.job_id=1;
    for (uint16_t message=1;message<=129;++message) {
        semantic.msg_id=message; source.tx_req_q.push(request);
    }
    for (size_t step=0;step<512 && source.hasPendingWork();++step) source.openChk();
    size_t requests=0;
    while (!source.tx_pkt_q.empty()) {
        requests+=source.tx_pkt_q.front().PDS_type==RUOD_req_header; source.tx_pkt_q.pop();
    }
    CHECK(requests==128 && source.tx_req_q.size()==1 && source.unack_cnt==128);
    CHECK(!source.peerWindowAllows(initial_sequence+128) && !source.hasPendingWork());
    source.freePDC(); CHECK(loop.pending()==0);
}

void configuration_validation() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1); fabric.add_host(2); fabric.add_link(1,2,{});
    PdsHost host(1,loop,trace,port);
    for (const auto bad:{0u,32641u}) {
        PsnRangeConfiguration settings; settings.local_packet_capacity=bad;
        check_throws<std::invalid_argument>([&] { host.configure_psn_ranges(settings); });
    }
    PsnRangeConfiguration settings; settings.default_mpr=256;
    check_throws<std::invalid_argument>([&] { host.configure_psn_ranges(settings); });
    settings.default_mpr=0; settings.advertised_mpr=256;
    check_throws<std::invalid_argument>([&] { host.configure_psn_ranges(settings); });
    settings.advertised_mpr=0;
    check_throws<std::invalid_argument>([&] { host.configure_psn_ranges(settings); });
    host.configure_psn_ranges(settings,4);
    CHECK(host.open_connection(2)!=UINT16_MAX);
    check_throws<std::logic_error>([&] { host.configure_psn_ranges({}); });
    host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const uint32_t start:{1000u,UINT32_MAX-64}) {
            all_default_encodings(start); initial_reduced_receive_window(start);
            cack_receive_boundary(start); initial_source_admission(start);
        }
        configuration_validation();
        std::cout<<"PASS: encoded Default_MPR, local cache separation, initial admission, CACK receive window and wrap\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
