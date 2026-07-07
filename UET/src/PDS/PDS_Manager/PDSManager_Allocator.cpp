#include "PDSManager.hpp"

PDS_Manager::AllocPDCResult PDS_Manager::allocPDC(uint16_t pdc_id,
                                                  uint32_t dst_fep,
                                                  uint32_t src_fep,
                                                  uint8_t delivery_mode)
{
    if (!pdc_list[pdc_id].is_open) {
        if (pdc_id >= MAX_PDC) {
            if (TPDC_Processmanager.createTPDCProcess(pdc_id, dst_fep, src_fep, static_cast<pdc_mode>(delivery_mode))) {
                pdc_list[pdc_id].is_open = true;
                open_cnt++;
            } else {
                LOG_ERROR("alloc_pdc", "Failed to create TPDC");
                return AllocPDCResult::CREATE_FAILED;
            }
        } else {
            if (IPDC_Processmanager.createIPDCProcess(pdc_id, dst_fep, src_fep, static_cast<pdc_mode>(delivery_mode))) {
                pdc_list[pdc_id].is_open = true;
                open_cnt++;
            } else {
                LOG_ERROR("alloc_pdc", "Failed to create IPDC");
                return AllocPDCResult::CREATE_FAILED;
            }
        }
        LOG_INFO("alloc_pdc", "PDC allocation successful, ID: " + std::to_string(pdc_id));
        return AllocPDCResult::CREATED;
    }
    return AllocPDCResult::ALREADY_OPEN;
}

bool PDS_Manager::assignPDC(uint16_t msgid, uint16_t pdc_id)
{
    LOG_INFO("assign_pdc", "Allocated PDC ID: " + std::to_string(pdc_id));
    if (pdc_list[pdc_id].is_open) {
        LOG_INFO("assign_pdc", "PDC already open, no need to reallocate, msgid: " + std::to_string(msgid));
        return true;
    }
    LOG_INFO("assign_pdc", "PDC ID: " + std::to_string(pdc_id) + " not open");
    return false;
}

bool PDS_Manager::assignPDC(uint32_t job_id,
                            uint32_t dest_fa,
                            uint8_t trafficclass,
                            uint8_t deliverymode,
                            uint16_t msgid,
                            uint16_t *pdc_id)
{
    int computed = muxTx2PDCID(job_id, dest_fa, trafficclass, deliverymode);
    if (computed < 0 || computed >= static_cast<int>(MAX_PDC * 2)) {
        LOG_WARN("assign_pdc",
                 "muxTx2PDCID failed (" + std::to_string(computed) + "), fallback to PDCID 0 for prototype");
        computed = 0;
    }
    *pdc_id = static_cast<uint16_t>(computed);
    LOG_INFO("assign_pdc", "Allocated PDC ID: " + std::to_string(*pdc_id));
    if (pdc_list[*pdc_id].is_open) {
        LOG_INFO("assign_pdc", "PDC already open, no need to reallocate, msgid: " + std::to_string(msgid));
        return true;
    }
    LOG_INFO("assign_pdc", "Applying for PDC ID: " + std::to_string(*pdc_id));
    return true;
}

int PDS_Manager::muxTx2PDCID(uint32_t job_id, uint32_t dest_fa, uint8_t trafficclass, uint8_t deliverymode)
{
    LOG_INFO("mux_tx_to_pdc_id",
             "PDC allocation algorithm - input parameters: " + std::to_string(job_id) + ", " +
                 std::to_string(dest_fa) + ", " + std::to_string(trafficclass) + ", " +
                 std::to_string(deliverymode));

    const uint32_t bank = hash_fa(dest_fa) & BANK_MASK;
    job_id *= 10;
    const uint64_t key = ((uint64_t)job_id << JOBID_SHIFT) |
                         ((uint64_t)dest_fa << DEST_FA_SHIFT) |
                         ((uint64_t)trafficclass << TC_SHIFT) |
                         ((uint64_t)deliverymode << DM_SHIFT);
    const uint16_t h1 = crc16_hash(key, CRC16_POLY1, HASH_SEED1);
    const uint32_t pick = h1 & (PDCs_PER_BANK - 1);
    const uint32_t pdcid = (bank << BANK_SHIFT) | pick;
    if (pdcid >= MAX_PDC) {
        LOG_ERROR("mux_tx_to_pdc_id", "Generated PDCID out of range: " + std::to_string(pdcid));
        return -1;
    }
    LOG_INFO("mux_tx_to_pdc_id",
             "PDC allocation algorithm - Bank: " + std::to_string(bank) + ", 选择索引: " +
                 std::to_string(pick) + ", 最终PDCID: " + std::to_string(pdcid));
    return static_cast<int>(pdcid);
}

int PDS_Manager::muxRx2PDCID(uint32_t src_addr, uint32_t dest_addr, uint16_t spdcid)
{
    LOG_INFO("mux_rx_to_pdc_id",
             "PDC allocation algorithm - input parameters: " + std::to_string(src_addr) + ", " +
                 std::to_string(dest_addr) + ", " + std::to_string(spdcid));

    const uint32_t bank = hash_fa(dest_addr) & BANK_MASK;
    spdcid *= 10;
    const uint64_t key = ((uint64_t)src_addr << JOBID_SHIFT) |
                         ((uint64_t)dest_addr << DEST_FA_SHIFT) |
                         ((uint64_t)spdcid << TC_SHIFT) |
                         ((uint64_t)0 << DM_SHIFT);
    const uint16_t h1 = crc16_hash(key, CRC16_POLY1, HASH_SEED1);
    const uint32_t pick = h1 & (PDCs_PER_BANK - 1);
    const uint32_t pdcid = (bank << BANK_SHIFT) | pick;
    if (pdcid >= MAX_PDC + MAX_PDC) {
        LOG_ERROR("mux_rx_to_pdc_id", "Generated PDCID out of range: " + std::to_string(pdcid));
        return -1;
    }
    LOG_INFO("mux_rx_to_pdc_id",
             "PDC allocation algorithm - Bank: " + std::to_string(bank) + ", 选择索引: " +
                 std::to_string(pick) + ", 最终PDCID: " + std::to_string(pdcid));
    return static_cast<int>(pdcid + MAX_PDC);
}

int PDS_Manager::selectPDC2Close()
{
    for (int i = 0; i < MAX_PDC; i++) {
        if (pdc_list[i].is_open && IPDC_Processmanager.canIPDCCloseInternal(i)) {
            LOG_INFO("select_pdc_2close", "Selecting PDC to close, ID: " + std::to_string(i));
            return i;
        }
    }
    LOG_WARN("select_pdc_2close", "No PDC available to close");
    return -1;
}
