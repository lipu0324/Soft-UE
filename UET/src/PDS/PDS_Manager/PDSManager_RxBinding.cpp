#include "PDSManager.hpp"

bool PDS_Manager::findRxBinding(const RxBindingKey &key, uint16_t *pdc_id) const
{
    if (pdc_id == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(rx_binding_mu_);
    const auto iter = rx_binding_map_.find(key);
    if (iter == rx_binding_map_.end()) {
        return false;
    }
    *pdc_id = iter->second;
    return true;
}

bool PDS_Manager::isSameBinding(uint16_t pdc_id, const RxBindingKey &key) const
{
    if (pdc_id >= MAX_PDC * 2) {
        return false;
    }
    const pdc &entry = pdc_list[pdc_id];
    return entry.is_open &&
           entry.has_binding &&
           entry.bound_src_fep == key.src_fep &&
           entry.bound_dst_fep == key.dst_fep &&
           entry.bound_remote_spdcid == key.remote_spdcid &&
           entry.bound_mode == key.delivery_mode;
}

void PDS_Manager::bindPdc(uint16_t pdc_id,
                          uint32_t src_fep,
                          uint32_t dst_fep,
                          uint16_t remote_spdcid,
                          uint8_t delivery_mode)
{
    if (pdc_id >= MAX_PDC * 2) {
        return;
    }
    pdc &entry = pdc_list[pdc_id];
    entry.has_binding = true;
    entry.bound_src_fep = src_fep;
    entry.bound_dst_fep = dst_fep;
    entry.bound_remote_spdcid = remote_spdcid;
    entry.bound_mode = delivery_mode;
}

void PDS_Manager::clearPdcBinding(uint16_t pdc_id)
{
    if (pdc_id >= MAX_PDC * 2) {
        return;
    }
    pdc &entry = pdc_list[pdc_id];
    entry.has_binding = false;
    entry.bound_src_fep = 0;
    entry.bound_dst_fep = 0;
    entry.bound_remote_spdcid = 0;
    entry.bound_mode = 0;
}

void PDS_Manager::bindRxConnection(const RxBindingKey &key, uint16_t pdc_id)
{
    std::lock_guard<std::mutex> lock(rx_binding_mu_);
    rx_binding_map_[key] = pdc_id;
}

void PDS_Manager::clearRxBindingsForPdc(uint16_t pdc_id)
{
    std::lock_guard<std::mutex> lock(rx_binding_mu_);
    for (auto iter = rx_binding_map_.begin(); iter != rx_binding_map_.end();) {
        if (iter->second == pdc_id) {
            iter = rx_binding_map_.erase(iter);
        } else {
            ++iter;
        }
    }
}

int PDS_Manager::findFallbackRxPdc(uint16_t preferred_pdcid) const
{
    if (preferred_pdcid < MAX_PDC || preferred_pdcid >= MAX_PDC * 2) {
        return -1;
    }

    const uint16_t bank_base =
        static_cast<uint16_t>(MAX_PDC + ((preferred_pdcid - MAX_PDC) / PDCs_PER_BANK) * PDCs_PER_BANK);
    for (uint16_t offset = 1; offset < PDCs_PER_BANK; ++offset) {
        const uint16_t candidate = static_cast<uint16_t>(bank_base + ((preferred_pdcid - bank_base + offset) % PDCs_PER_BANK));
        if (!pdc_list[candidate].is_open && !pdc_list[candidate].has_binding) {
            return candidate;
        }
    }

    for (uint16_t candidate = MAX_PDC; candidate < MAX_PDC * 2; ++candidate) {
        if ((candidate >= bank_base) && (candidate < bank_base + PDCs_PER_BANK)) {
            continue;
        }
        if (!pdc_list[candidate].is_open && !pdc_list[candidate].has_binding) {
            return candidate;
        }
    }
    return -1;
}
