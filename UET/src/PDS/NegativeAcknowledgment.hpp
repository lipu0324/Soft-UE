#pragma once
#include <cstdint>
#include <optional>

namespace UET::PDS {
enum class NegativeAcknowledgmentAction { Retransmit, CloseConnection, NewStartSequence };
struct NegativeAcknowledgmentPolicy {
    NegativeAcknowledgmentAction action;
    uint8_t delay_group=0;
};

// UE 1.1 Table 3-68. A reserved code has no action and must not establish a
// peer identity, debit CMS, pause a PDC, or alter a retry timer. Delay-group
// selection is a documented local policy, separate from the normative action.
inline std::optional<NegativeAcknowledgmentPolicy> negative_acknowledgment_policy(uint8_t code) {
    using Action=NegativeAcknowledgmentAction;
    switch (code) {
    case 0x01: case 0x02: // Trimmed / last-hop trimmed.
    case 0x0b: case 0x0d: // Window / ordered-delivery gap.
    case 0x12: case 0x14: // Missing packet / query for a response with data.
    case 0x1a: case 0xfd: // Receiver-inferred loss / experimental normal.
        return NegativeAcknowledgmentPolicy{Action::Retransmit,0};
    case 0x04: case 0x05: case 0x06: // No PDC / CCC / receive bitmap.
    case 0x07: case 0x08: case 0x09: // No packet / guaranteed response / SES message buffer.
    case 0x0a: case 0x1b: // Generic resource / SES synchronization state.
        return NegativeAcknowledgmentPolicy{Action::Retransmit,1};
    case 0x18: // SES is still processing; its eventual ACK may beat the delayed retry.
        return NegativeAcknowledgmentPolicy{Action::Retransmit,2};
    case 0x0e: case 0x0f: case 0x10: case 0x11: case 0x13:
    case 0x15: case 0x16: case 0x19: case 0xfe: case 0xff:
        // §3.5.12.7 permits failing the RETRY-marked PDC_ERR/PDC_FATAL
        // cases to SES. Automatic connection replay is not our default policy.
        return NegativeAcknowledgmentPolicy{Action::CloseConnection,0};
    case 0x17:
        return NegativeAcknowledgmentPolicy{Action::NewStartSequence,0};
    default: return {}; // Includes 0x03, which was defined in older revisions.
    }
}
}
