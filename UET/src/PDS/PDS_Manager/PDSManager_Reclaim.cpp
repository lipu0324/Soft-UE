#include "PDSManager.hpp"

void PDS_Manager::resourceCheck()
{
    LOG_INFO("resource_check", "=====================Resource Check=====================");
    const bool need_pressure_close = pend_cnt > 0 || (open_cnt - closing_cnt > Close_Thresh);
    const bool have_idle_candidates = open_cnt > closing_cnt;
    if (need_pressure_close || have_idle_candidates) {
        while (!pend_q.empty()) {
            if (isPendNodeOverTime(pend_q.front())) {
                LOG_WARN("resource_check",
                         "First wait node timed out, removed, remaining wait count: " + std::to_string(pend_cnt));
                pend_node node = pend_q.front();
                pend_q.pop();
                pendTimeOut(node);
            } else {
                break;
            }
        }
        const uint16_t sPDCID = selectPDC2Close();
        if (sPDCID == static_cast<uint16_t>(-1)) {
            LOG_WARN("resource_check", "No PDC available to close, not closing for now");
        } else {
            if (IPDC_Processmanager.sendCloseReq(sPDCID)) {
                closing_cnt++;
                LOG_INFO("resource_check",
                         "Resource check: closing PDC, closing count: " + std::to_string(closing_cnt));
            } else {
                LOG_DEBUG("resource_check",
                          "Skipped close request for PDCID " + std::to_string(sPDCID) +
                              " because it is already closing");
            }
        }
    } else {
        LOG_INFO("resource_check", "Resource check: no need to close PDC");
    }
}

int PDS_Manager::requestCloseAllOpenIPDCs()
{
    int requested = 0;
    for (int i = 0; i < MAX_PDC; ++i) {
        if (!pdc_list[i].is_open) {
            continue;
        }
        if (!IPDC_Processmanager.canIPDCCloseInternal(static_cast<uint16_t>(i))) {
            continue;
        }
        if (IPDC_Processmanager.sendCloseReq(static_cast<uint16_t>(i))) {
            ++closing_cnt;
            ++requested;
        }
    }
    LOG_INFO("request_close_all_ipdc",
             "Requested close for " + std::to_string(requested) + " open IPDC(s)");
    return requested;
}

bool PDS_Manager::PDCClose()
{
    LOG_INFO("pdc_close", "=====================PDC Close Request=====================");
    uint16_t pdc_id = MAX_PDC * 2;
    PDC_close_q.pop(pdc_id);
    LOG_INFO("pdc_close", "Popped PDC ID from close queue: " + std::to_string(pdc_id));
    if (pdc_id >= MAX_PDC * 2) {
        LOG_ERROR("pdc_close", "PDC ID out of range: " + std::to_string(pdc_id));
        return false;
    }
    if (!pdc_list[pdc_id].is_open) {
        LOG_WARN("pdc_close", "PDC ID: " + std::to_string(pdc_id) + " already closed");
        return false;
    }

    pdc_list[pdc_id].is_open = false;
    clearPdcBinding(pdc_id);
    clearRxBindingsForPdc(pdc_id);
    switch (getPDCType(pdc_id)) {
        case PDC_TYPE::IPDC:
            LOG_INFO("pdc_close", "Closing IPDC ID: " + std::to_string(pdc_id));
            IPDC_Processmanager.stopIPDCProcess(pdc_id);
            open_cnt--;
            if (closing_cnt > 0) {
                closing_cnt--;
            }
            break;
        case PDC_TYPE::TPDC:
            LOG_INFO("pdc_close", "Closing TPDC ID: " + std::to_string(pdc_id));
            TPDC_Processmanager.stopTPDCProcess(pdc_id);
            open_cnt--;
            break;
        default:
            LOG_ERROR("pdc_close", "Unknown PDC type: " + std::to_string(pdc_id));
            return false;
    }

    LOG_INFO("pdc_close", "PDC ID: " + std::to_string(pdc_id) + " close successful");
    return true;
}
