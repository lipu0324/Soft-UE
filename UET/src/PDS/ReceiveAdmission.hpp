#pragma once
#include "../Transport_Layer.hpp"

namespace UET::PDS {
// A metadata-only reservation request, not a delivered SES packet. There is
// no RX handle yet and payload bytes must not be copied or processed here.
inline PDC_SES_req semantic_admission_request(const PDStoNET_pkt& packet,uint16_t local_pdc,
                                             uint32_t peer,pdc_mode mode,uint32_t start_psn) {
    PDC_SES_req request{};
    request.PDCID=local_pdc; request.rx_pkt_handle=UINT16_MAX;
    request.pkt.bth_type=packet.SESpkt.bth_type;
    request.pkt.bth_header=packet.SESpkt.bth_header;
    // Group admission needs the synchronized extension before a PSN is
    // accepted. Copy only fixed metadata, never the unadmitted payload.
    request.pkt.eth_type=packet.SESpkt.eth_type;
    request.pkt.eth_header=packet.SESpkt.eth_header;
    request.next_hdr=packet.PDS_header.RUOD_req_header.next_hdr;
    request.orig_pdcid=packet.PDS_header.RUOD_req_header.spdcid;
    request.orig_psn=packet.PDS_header.RUOD_req_header.psn;
    request.source_fep=peer; request.delivery_mode=mode;
    request.connection_start_psn=start_psn;
    return request;
}
}
