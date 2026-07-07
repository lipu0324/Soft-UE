#ifndef PDS_MANAGER_INTERNAL_HPP
#define PDS_MANAGER_INTERNAL_HPP

#include "../../Transport_Layer.hpp"

namespace UET::PDSInternal {

struct RxPacketRoute
{
    bool recognized = false;
    bool is_request = false;
    bool syn = false;
    uint16_t dpdcid = 0;
    uint16_t spdcid = 0;
};

inline RxPacketRoute inspectRxPacketRoute(const PDStoNET_pkt &pkt)
{
    RxPacketRoute route{};
    switch (pkt.PDS_type) {
        case RUOD_req_header:
            route.recognized = true;
            route.is_request = true;
            route.syn = pkt.PDS_header.RUOD_req_header.flags.syn != 0;
            route.dpdcid = pkt.PDS_header.RUOD_req_header.dpdcid;
            route.spdcid = pkt.PDS_header.RUOD_req_header.spdcid;
            break;
        case RUOD_cp_header:
            route.recognized = true;
            route.is_request = true;
            route.syn = pkt.PDS_header.RUOD_cp_header.flags.syn != 0;
            route.dpdcid = pkt.PDS_header.RUOD_cp_header.dpdcid;
            route.spdcid = pkt.PDS_header.RUOD_cp_header.spdcid;
            break;
        case RUOD_ack_header:
            route.recognized = true;
            route.dpdcid = pkt.PDS_header.RUOD_ack_header.dpdcid;
            route.spdcid = pkt.PDS_header.RUOD_ack_header.spdcid;
            break;
        case nack_header:
            route.recognized = true;
            route.dpdcid = pkt.PDS_header.nack_header.dpdcid;
            route.spdcid = pkt.PDS_header.nack_header.spdcid;
            break;
        default:
            break;
    }
    return route;
}

} // namespace UET::PDSInternal

#endif
