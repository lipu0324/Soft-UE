#pragma once
#include "PdcEvents.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>

namespace UET::Runtime {
// Host-owned continuation of the native SES message-ID lease. Destroying SES
// does not make queued PDS packets or their local upcalls disappear. IDs stay
// unavailable until real transport retirement; no timer guesses delivery.
class RetiredSemanticMessages {
public:
    struct Lease {
        uint32_t peer;
        std::optional<uint32_t> job;
        uint16_t local_pdc=UINT16_MAX;
        uint32_t connection_start_psn=0,last_psn=0;
        bool end_transmitted=false,datagram=false,requires_connection_retirement=false;
        bool close_requested=false;
    };
    bool contains(uint16_t message) const { return leases_.count(message)!=0; }
    std::size_t size() const { return leases_.size(); }
    void clear() { leases_.clear(); } // Host shutdown has stopped every local PDS owner.
    void retain(uint16_t message,Lease lease) { leases_.insert_or_assign(message,std::move(lease)); }
    void datagram_completed(uint16_t message) {
        const auto found=leases_.find(message);
        if (found!=leases_.end() && found->second.datagram) leases_.erase(found);
    }
    void observe(const PdcEvent& event,uint16_t source_pdc_limit) {
        if (event.kind==PdcEventKind::RequestTransmitted || event.kind==PdcEventKind::RequestRejected) {
            const auto found=leases_.find(event.message_id);
            if (found==leases_.end()) return;
            auto& lease=found->second;
            if (lease.datagram || lease.peer!=event.peer || (lease.job && *lease.job!=event.job)) return;
            if (event.local_pdc>=source_pdc_limit) {
                // Manager admission failure has no PDC. It removes the whole
                // unsent message; it cannot retire an already-bound lease.
                if (event.kind==PdcEventKind::RequestRejected && event.local_pdc==UINT16_MAX && lease.local_pdc==UINT16_MAX)
                    leases_.erase(found);
                return;
            }
            if (lease.local_pdc!=UINT16_MAX && !same_connection(lease,event)) return;
            if (event.kind==PdcEventKind::RequestRejected) { leases_.erase(found); return; }
            lease.local_pdc=event.local_pdc; lease.connection_start_psn=event.connection_start_psn;
            lease.job=event.job;
            // A retransmitted earlier fragment cannot move EOM backwards.
            if (event.end_of_message) { lease.last_psn=event.sequence; lease.end_transmitted=true; }
            return;
        }
        if (event.kind!=PdcEventKind::TransmitCleared && event.kind!=PdcEventKind::ConnectionClosed) return;
        for (auto found=leases_.begin();found!=leases_.end();) {
            const auto& lease=found->second;
            const bool cleared=event.kind==PdcEventKind::TransmitCleared && lease.end_transmitted &&
                !lease.requires_connection_retirement && event.sequence-lease.last_psn<0x80000000u;
            if (!lease.datagram && same_connection(lease,event) && (event.kind==PdcEventKind::ConnectionClosed || cleared))
                found=leases_.erase(found);
            else ++found;
        }
    }
    template<class RequestClose> void request_read_retirement(RequestClose request_close) {
        for (auto& entry:leases_) {
            auto& lease=entry.second;
            if (lease.requires_connection_retirement && lease.local_pdc!=UINT16_MAX && !lease.close_requested)
                lease.close_requested=request_close(lease.local_pdc);
        }
    }
private:
    std::map<uint16_t,Lease> leases_; // At most65535 IDs, shared with the active native Endpoint namespace.
    static bool same_connection(const Lease& lease,const PdcEvent& event) {
        return lease.local_pdc!=UINT16_MAX && lease.peer==event.peer && lease.local_pdc==event.local_pdc &&
            lease.connection_start_psn==event.connection_start_psn;
    }
};
} // namespace UET::Runtime
