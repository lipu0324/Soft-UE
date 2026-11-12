#include "Check.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include <iostream>

class InspectableTarget : public T_PDC {
public:
    using T_PDC::T_PDC;
    using PDC::clearReceivedPacketsThrough;
};

int main() {
    try {
        UET::Runtime::EventLoop event_loop;
        UET::Runtime::Services services{event_loop,event_loop,[]{}};
        InspectableTarget target(&services);
        CHECK(target.initPDC(MAX_PDC));
        target.mode=RUD; target.state=ESTABLISHED;
        target.start_psn=UINT32_MAX-1;
        target.rx_cur_psn=target.cack_psn=target.rx_clear_psn=UINT32_MAX-2;
        auto receive=[&](uint32_t sequence,bool guaranteed_response) {
            PDStoNET_pkt packet{};
            packet.PDS_type=RUOD_req_header;
            packet.PDS_header.RUOD_req_header.type=RUD_REQ;
            packet.PDS_header.RUOD_req_header.psn=sequence;
            packet.PDS_header.RUOD_req_header.clear_psn_off=static_cast<int16_t>((UINT32_MAX-2)-sequence);
            target.chkRxError(&packet); CHECK(target.error_chk==OPEN);
            const auto handle=target.processRxReq(&packet);
            auto metadata=target.rx_pkt_map.at(handle);
            target.updateRxPsnTracker(&metadata);
            target.updateRxPsnTracker(&metadata,guaranteed_response);
            if (guaranteed_response) target.sendAck(UET_HDR_NONE,0,0,sequence,nullptr,true);
            return packet;
        };
        auto last=receive(0,false); // Arrives first, after the sequence-number wrap.
        CHECK(target.rx_cur_psn==UINT32_MAX-2 && target.cack_psn==UINT32_MAX-2);
        target.chkRxError(&last); CHECK(target.error_chk==ACK_ERROR);
        receive(UINT32_MAX-1,true); // A response now blocks cumulative acknowledgement.
        receive(UINT32_MAX,false);
        CHECK(target.rx_cur_psn==0 && target.cack_psn==UINT32_MAX-2);
        target.clearReceivedPacketsThrough(1); // Cannot clear a packet never received.
        CHECK(target.cack_psn==UINT32_MAX-2);
        target.clearReceivedPacketsThrough(UINT32_MAX-1);
        CHECK(target.cack_psn==0 && target.tx_ack_buffer.empty());
        target.clearReceivedPacketsThrough(0);
        target.chkRxError(&last); CHECK(target.error_chk==DROP);
        last.PDS_header.RUOD_req_header.psn=100;
        target.chkRxError(&last); CHECK(target.error_chk==DROP); // Receive-window bound.
        target.freePDC(); CHECK(event_loop.pending()==0);
        std::cout<<"PASS: RUD receive window, holes, duplicates, guaranteed-response clear and 32-bit wrap\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
