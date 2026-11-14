#pragma once
#include <cstdint>

namespace UET::Runtime {
// Local NIC-to-PDS metadata, never encoded into a UE packet. Incarnation
// disambiguates a recycled PDC ID even when tests reuse the same starting PSN.
enum class TransmitKind : uint8_t { Request, NumberedControl, SemanticQuery, Probe, RudiRequest };
struct TransmitIdentity {
    uint16_t local_pdc=0;
    uint32_t connection_start_psn=0;
    uint64_t incarnation=0;
    uint32_t sequence=0; // PSN for PDC traffic; locally unique packet ID for RudiRequest.
    uint64_t attempt=0; // Monotonic across retries, including the infinite-retry configuration.
    uint16_t opaque=0;
    TransmitKind kind=TransmitKind::Request;
    bool synchronizing=false;
};
enum class TransmitOutcome : uint8_t { Started, Rejected };
struct TransmitNotification {
    TransmitIdentity identity;
    uint64_t time_ns=0;
    TransmitOutcome outcome=TransmitOutcome::Started;
};
}
