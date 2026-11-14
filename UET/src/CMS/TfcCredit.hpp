#pragma once
#include "Nscc.hpp" // Shared 24-bit, 256-byte cumulative-counter decoder.
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace UET::CMS {

struct TfcSourceConfig {
    uint32_t payload_mtu_bytes=4096;
    uint32_t destination_cell_bytes=256;
    uint32_t packet_overhead_bytes=256;
    int64_t initial_credit_bytes=256;

    void validate() const {
        // §3.6.15: destination cells are256..9216B in256B steps. The
        // normative deployment MTUs are1024/2048/4096/8192; smaller MTUs
        // remain available for the simulator's boundary experiments.
        if (!payload_mtu_bytes || payload_mtu_bytes>8192 || destination_cell_bytes<256 ||
            destination_cell_bytes>9216 || destination_cell_bytes%256 || packet_overhead_bytes>256 ||
            initial_credit_bytes<static_cast<int64_t>(packet_overhead_bytes))
            throw std::invalid_argument("invalid TFC cell, payload MTU, overhead or initial byte credit");
    }
};

// The pure source credit law (§3.6.15), separate from PDS ownership, timers,
// wire encoding and destination buffer allocation. It is not an enabled CMS
// policy by itself. Callers serialize admission/debit on the injected runtime.
class TfcSourceCredit {
public:
    explicit TfcSourceCredit(TfcSourceConfig config={})
        :config_(config),credit_bytes_(config.initial_credit_bytes) { config_.validate(); }

    const TfcSourceConfig& config() const { return config_; }
    int64_t available_credit_bytes() const { return credit_bytes_; }

    uint32_t packet_credit_bytes(uint64_t payload_bytes) const {
        if (payload_bytes>config_.payload_mtu_bytes) throw std::invalid_argument("TFC payload exceeds configured MTU");
        const uint64_t storage_bytes=payload_bytes+config_.packet_overhead_bytes;
        const uint64_t cells=(storage_bytes+config_.destination_cell_bytes-1)/config_.destination_cell_bytes;
        return static_cast<uint32_t>(cells*config_.destination_cell_bytes);
    }

    bool can_send(bool retransmission=false) const {
        // Credit permits one MTU-sized packet whenever it is positive,
        // even if that packet consumes more than the current balance.
        return retransmission || credit_bytes_>0;
    }

    uint32_t on_send(uint64_t payload_bytes,bool retransmission=false) {
        const auto consumed=packet_credit_bytes(payload_bytes);
        // Retransmission identity must come from the local PDS TX owner,
        // never an untrusted peer flag. Its receive buffer was already
        // covered by the original packet's debit (§3.6.15).
        if (retransmission) return 0;
        if (!can_send()) throw std::logic_error("TFC has no credit for a new packet");
        // A signed balance is necessary: legal one-packet overshoot must
        // block subsequent new data, rather than wrap to huge credit.
        credit_bytes_-=consumed;
        return consumed;
    }

    uint64_t on_credit_update(uint32_t cumulative_wire_units) {
        if (cumulative_wire_units>0xffffff) throw std::invalid_argument("TFC cumulative credit exceeds24 bits");
        // §§3.6.10.4/3.6.15 define one wire unit as256B. Reuse the
        // forward-half serial arithmetic also used by NSCC byte telemetry,
        // but retain an independent counter for credit grants. The TFC
        // pseudocode's >>8 contradicts these units and RCCC's <<8; see
        // DOC/ue11/TRANSPORT-FLOW-CONTROL.md for the recorded discrepancy.
        auto next_counter=grant_counter_;
        const auto added_bytes=next_counter.acknowledge(cumulative_wire_units);
        if (credit_bytes_>std::numeric_limits<int64_t>::max()-static_cast<int64_t>(added_bytes))
            throw std::overflow_error("TFC byte credit exhausted signed accounting range");
        // Commit both fields together. A rejected overflow must not consume
        // the cumulative grant and silently lose that update on a retry.
        credit_bytes_+=static_cast<int64_t>(added_bytes);
        grant_counter_=next_counter;
        return added_bytes;
    }

private:
    const TfcSourceConfig config_; // Cell/overhead choices cannot change on an active PDC.
    int64_t credit_bytes_;
    ReceivedByteCounter grant_counter_;
};

} // namespace UET::CMS
