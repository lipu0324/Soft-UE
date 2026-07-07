#include "PDSManager.hpp"

#include "PDSManagerInternal.hpp"

namespace {

template <typename T>
bool popLocalQueue(std::queue<T> &queue, std::mutex &mutex, T &out)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (queue.empty()) {
        return false;
    }
    out = queue.front();
    queue.pop();
    return true;
}

} // namespace

bool PDS_Manager::checkRxPkt(PDStoNET_pkt *rx)
{
    return rx != nullptr;
}

PDS_Nack_Codes PDS_Manager::checkUnexpectEvent(PDStoNET_pkt *rx)
{
    if (rx != nullptr) {
        return UET_TRIMMED;
    }
    return reserved;
}

void PDS_Manager::unexpectedOrRxOOR(PDStoNET_pkt *rx)
{
    LOG_INFO("unexpected_or_rx_oor", "=====================Entering RX OOR Queue=====================");
    if (isOOR()) {
        sendNack(rx, UET_NO_PDC_AVAIL);
        LOG_WARN("unexpected_or_rx_oor", "Currently in OOR state, sending resource insufficient NACK");
    }
    const bool enable_nack = rx->PDS_type == RUOD_req_header;
    if (enable_nack) {
        LOG_WARN("unexpected_or_rx_oor", "Unexpected RX packet, sending NACK");
        sendNack(rx, checkUnexpectEvent(rx));
    }
    event_cnt++;
    LOG_INFO("unexpected_or_rx_oor",
             "Error event processing completed: RX OOR, event count: " + std::to_string(event_cnt));
    resourceCheck();
}

void PDS_Manager::rxPkt()
{
    LOG_INFO("rx_pkt", "=====================Processing Network Layer Packet=====================");
    bool is_fwd_pkt = false;
    uint16_t pdc_id = 0;
    PDStoNET_pkt rx_pkt{};
    if (!popLocalQueue(Net_rx_pkt_q, local_queue_mutex_, rx_pkt)) {
        return;
    }
    PDStoNET_pkt *rx = &rx_pkt;

    if (!checkRxPkt(rx)) {
        LOG_ERROR("rx_pkt", "RX packet invalid");
        unexpectedOrRxOOR(rx);
        return;
    }

    const UET::PDSInternal::RxPacketRoute route = UET::PDSInternal::inspectRxPacketRoute(*rx);
    LOG_INFO("rx_pkt", "RX packet valid, starting processing...");
    if (route.is_request) {
        pdc_id = route.dpdcid;
        if (pdc_id >= MAX_PDC * 2) {
            LOG_ERROR("rx_pkt", "RX packet dpdcid out of range: " + std::to_string(pdc_id) + ", dropping");
            is_fwd_pkt = false;
        } else if (!route.syn) {
            LOG_INFO("rx_pkt", "RX packet type: RUOD request, PDCID: " + std::to_string(pdc_id));
        } else {
            LOG_INFO("rx_pkt", "RX packet type: RUOD establishment request ");
        }

        if (!route.syn && pdc_list[pdc_id].is_open) {
            LOG_INFO("rx_pkt", "RX packet target PDC is open");
            is_fwd_pkt = true;
        } else {
            LOG_INFO("rx_pkt", "RX packet target PDC is not open");
            if (route.syn) {
                if (isOOR()) {
                    is_fwd_pkt = false;
                    LOG_WARN("rx_pkt", "PDC full, cannot establish new connection, dropping");
                } else {
                    const uint8_t delivery_mode =
                        (rx->PDS_header.RUOD_req_header.type == RUD_REQ) ? RUD : ROD;
                    const RxBindingKey key{rx->src_fep, rx->dst_fep, route.spdcid, delivery_mode};
                    uint16_t bound_pdcid = 0;
                    if (findRxBinding(key, &bound_pdcid)) {
                        pdc_id = bound_pdcid;
                        if (pdc_id < MAX_PDC * 2 && pdc_list[pdc_id].is_open && isSameBinding(pdc_id, key)) {
                            LOG_INFO("rx_pkt", "Reuse bound TPDC for SYN, PDCID: " + std::to_string(pdc_id));
                            is_fwd_pkt = true;
                        } else {
                            LOG_ERROR("rx_pkt",
                                      "RX binding table mismatch for SYN, PDCID: " + std::to_string(pdc_id) +
                                          ", incoming_src_fep: " + std::to_string(key.src_fep) +
                                          ", incoming_dst_fep: " + std::to_string(key.dst_fep) +
                                          ", incoming_spdcid: " + std::to_string(key.remote_spdcid) +
                                          ", incoming_mode: " + std::to_string(key.delivery_mode));
                            sendNack(rx, UET_UNEXP_EVENT);
                            resourceCheck();
                            return;
                        }
                    } else {
                        const int preferred = muxRx2PDCID(rx->src_fep, rx->dst_fep, route.spdcid);
                        if (preferred < 0 || preferred >= MAX_PDC * 2) {
                            LOG_ERROR("rx_pkt",
                                      "Failed to allocate RX PDCID (muxRx2PDCID returned " +
                                          std::to_string(preferred) + "), dropping");
                            is_fwd_pkt = false;
                        } else {
                            pdc_id = static_cast<uint16_t>(preferred);
                            if (!pdc_list[pdc_id].is_open && !pdc_list[pdc_id].has_binding) {
                                const AllocPDCResult alloc_result =
                                    allocPDC(pdc_id, rx->src_fep, rx->dst_fep, delivery_mode);
                                if (alloc_result == AllocPDCResult::CREATED) {
                                    bindPdc(pdc_id, key.src_fep, key.dst_fep, key.remote_spdcid, key.delivery_mode);
                                    bindRxConnection(key, pdc_id);
                                    LOG_INFO("rx_pkt", "Allocate PDC, ID: " + std::to_string(pdc_id));
                                    is_fwd_pkt = true;
                                } else {
                                    LOG_ERROR("rx_pkt", "Failed to create TPDC for SYN packet, dropping");
                                    is_fwd_pkt = false;
                                }
                            } else if (isSameBinding(pdc_id, key)) {
                                bindRxConnection(key, pdc_id);
                                LOG_INFO("rx_pkt", "Reuse active TPDC for same-binding SYN, PDCID: " + std::to_string(pdc_id));
                                is_fwd_pkt = true;
                            } else {
                                const int fallback = findFallbackRxPdc(pdc_id);
                                if (fallback >= MAX_PDC && fallback < MAX_PDC * 2) {
                                    pdc_id = static_cast<uint16_t>(fallback);
                                    const AllocPDCResult alloc_result =
                                        allocPDC(pdc_id, rx->src_fep, rx->dst_fep, delivery_mode);
                                    if (alloc_result == AllocPDCResult::CREATED) {
                                        bindPdc(pdc_id, key.src_fep, key.dst_fep, key.remote_spdcid, key.delivery_mode);
                                        bindRxConnection(key, pdc_id);
                                        LOG_INFO("rx_pkt", "Allocate fallback TPDC, preferred: " +
                                                               std::to_string(preferred) + ", fallback: " +
                                                               std::to_string(pdc_id));
                                        is_fwd_pkt = true;
                                    } else {
                                        LOG_ERROR("rx_pkt", "Failed to create fallback TPDC for SYN packet");
                                        is_fwd_pkt = false;
                                    }
                                } else {
                                    LOG_ERROR("rx_pkt",
                                              "No fallback TPDC available for SYN collision, preferred PDCID: " +
                                                  std::to_string(pdc_id));
                                    sendNack(rx, UET_NO_PDC_AVAIL);
                                    resourceCheck();
                                    return;
                                }
                            }
                        }
                    }
                }
            } else {
                LOG_INFO("rx_pkt", "Non-connection initiation packet, illegal, dropping");
            }
        }
    } else if (rx->PDS_type == RUOD_ack_header ||
               rx->PDS_type == RUOD_cp_header ||
               rx->PDS_type == nack_header) {
        if (route.dpdcid < MAX_PDC * 2 && pdc_list[route.dpdcid].is_open) {
            std::string pkt_kind = "control";
            if (rx->PDS_type == RUOD_ack_header) {
                pkt_kind = "RUOD ack";
            } else if (rx->PDS_type == RUOD_cp_header) {
                pkt_kind = "RUOD cp";
            } else if (rx->PDS_type == nack_header) {
                pkt_kind = "RUOD nack";
            }
            LOG_INFO("rx_pkt", "RX packet type: " + pkt_kind + ", PDCID: " + std::to_string(route.dpdcid));
            pdc_id = route.dpdcid;
            is_fwd_pkt = true;
        }
    }

    if (is_fwd_pkt) {
        LOG_INFO("rx_pkt", "RX packet type: RUOD request, PDCID: " + std::to_string(pdc_id));
        fwdPkt2PDC(rx, pdc_id);
    } else {
        LOG_WARN("rx_pkt", "Unexpected RX packet, entering RX OOR processing");
        unexpectedOrRxOOR(rx);
    }
}
