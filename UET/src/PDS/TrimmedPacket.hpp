#pragma once
#include "../Transport_Layer.hpp"

namespace UET::PDS {
// §3.5.8.2 / §3.5.15.1: an unvalidated trimmed header may identify a loss,
// but must never allocate a PDC, acknowledge a PSN or expose SES bytes.
inline PDStoNET_pkt trimmed_negative_ack(const PDStoNET_pkt& received,uint16_t local_pdc=0,uint32_t expected_psn=0) {
    PDStoNET_pkt reply{};
    reply.src_fep=received.dst_fep; reply.dst_fep=received.src_fep;
    reply.PDS_type=nack_header; reply.wire_entropy=received.wire_entropy;
    auto& nack=reply.PDS_header.nack_header;
    nack.type=NACK; nack.next_hdr=UET_HDR_NONE;
    nack.flags.m=received.network_ecn==3;
    nack.flags.retx=received.PDS_header.RUOD_req_header.flags.retx;
    nack.nack_code=received.trimmed_last_hop?UET_TRIMMED_LASTHOP:UET_TRIMMED;
    nack.nack_psn=received.PDS_header.RUOD_req_header.psn;
    nack.spdcid=local_pdc; nack.dpdcid=received.PDS_header.RUOD_req_header.spdcid;
    nack.payload=local_pdc && is_reliable_ordered_request(received.PDS_header.RUOD_req_header.type)?expected_psn:0;
    return reply;
}
} // namespace UET::PDS
