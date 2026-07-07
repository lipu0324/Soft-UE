#ifndef PDC_RUD_INTERNALS_HPP
#define PDC_RUD_INTERNALS_HPP

#include "PDC.hpp"
#include "../PDS_Manager/PDSManager.hpp"
#include <cstring>
#include <list>
#include <mutex>

inline constexpr size_t kRudSackBitmapBytes = sizeof(uint32_t);
inline constexpr uint32_t kRudArrivalBlockSize = 64;
inline constexpr size_t kRudHotBlockCount = 4;
inline constexpr uint32_t kSesMaxMtu = 4096;
inline constexpr uint8_t kSendOpcode = 1;
inline constexpr uint8_t kWriteOpcode = 3;
inline constexpr uint8_t kReadOpcode = 2;

inline int64_t calcUnexpectedPartialTimeoutMs()
{
    int64_t total = 0;
    for (int retry = 0; retry <= Max_RTO_Retx_Cnt; ++retry) {
        total += static_cast<int64_t>(Base_RTO) * (1LL << retry);
    }
    return total;
}

inline const int64_t kUnexpectedPartialTimeoutMs = calcUnexpectedPartialTimeoutMs();
inline const int64_t kUnexpectedAcceptedTimeoutMs = kUnexpectedPartialTimeoutMs * 2;

struct UnexpectedSendRegistryEntry
{
    PDC *owner{nullptr};
    RxMessageKey key{};
    uint64_t job_id{0};
    uint16_t pdcid{0};
    uint32_t src_fep{0};
};

struct RequestTxRegistryEntry
{
    PDC *owner{nullptr};
    uint64_t job_id{0};
    uint16_t msg_id{0};
    uint32_t dst_fep{0};
};

extern std::mutex g_unexpected_send_registry_mu;
extern std::list<UnexpectedSendRegistryEntry> g_unexpected_send_registry;
extern std::mutex g_request_tx_registry_mu;
extern std::list<RequestTxRegistryEntry> g_request_tx_registry;

inline uint32_t loadSackBitmap(const UET::PayloadHandle &payload)
{
    if (payload.size() < kRudSackBitmapBytes || !payload.data()) {
        return 0;
    }
    uint32_t bitmap = 0;
    std::memcpy(&bitmap, payload.data(), sizeof(bitmap));
    return bitmap;
}

inline void storeSackBitmap(UET::PayloadHandle &payload, uint32_t bitmap)
{
    payload.allocate(kRudSackBitmapBytes);
    if (!payload.data()) {
        return;
    }
    std::memcpy(payload.data(), &bitmap, sizeof(bitmap));
}

#endif
