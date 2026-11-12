#pragma once
#include <cstdint>

namespace UET::Runtime {
enum class PdcEventKind {
    RequestTransmitted, PeerCumulativeAcknowledged, ReceiveCleared, ConnectionClosed,
    RequestRejected, TransmitCleared
};
enum class PdcFailureReason { None, RetryExhausted, FatalNegativeAcknowledgement, ResourcesUnavailable };

// Local control-plane metadata, never a wire header. PDS publishes facts;
// SES uses them to retire message state and report a terminal failure.
struct PdcEvent {
    PdcEventKind kind;
    uint16_t local_pdc;
    uint32_t peer;
    uint32_t connection_start_psn;
    uint32_t sequence;
    uint32_t job=0;
    uint16_t message_id=0;
    PdcFailureReason failure=PdcFailureReason::None;
    bool end_of_message=false;
};
} // namespace UET::Runtime
