#pragma once
#include "Nscc.hpp"
#include "../Transport_Layer.hpp"
#include <tuple>

namespace UET::CMS {
// Local PDC incarnation, independent of the peer's numeric PDCID. The starting
// PSN prevents a recycled local ID from inheriting stale congestion state.
struct Connection {
    uint32_t peer=0;
    uint16_t local_pdc=0;
    uint32_t starting_psn=0;
    bool ordered=false;
    auto identity() const { return std::make_tuple(peer,local_pdc,starting_psn,ordered); }
    bool operator<(const Connection& other) const { return identity()<other.identity(); }
};

struct CreditControlMessage {
    PDS_ctl_type subtype=Credit;
    uint32_t payload=0;
};

// PDS owns packet ordering, retries and duplicate suppression. CMS owns sending
// admission, nominal-byte accounting and feedback. All callbacks execute on the
// owning injected runtime; implementations must not synchronously re-enter PDS.
class ICongestionControl {
public:
    virtual ~ICongestionControl()=default;
    // §3.6.8.1.1: bind a CCC when the PDC's peer/mode/epoch are known,
    // including a control-only connection that has not sent any data.
    virtual void opened(const Connection&) {}
    virtual bool can_send(const Connection& connection)=0;
    virtual uint32_t transmitted(const Connection& connection,PDStoNET_pkt& packet)=0;
    // §3.6.15: TFC charges only a new packet, while NSCC accounts every
    // transmission attempt. PDS supplies retry ownership from its TX cache;
    // a received flag must never grant the free-retransmission exception.
    // Existing policies retain their behavior through these default adapters.
    virtual bool can_send_attempt(const Connection& connection,bool retransmission) {
        return can_send(connection);
    }
    virtual uint32_t transmitted_attempt(const Connection& connection,PDStoNET_pkt& packet,bool retransmission) {
        return transmitted(connection,packet);
    }
    // Optional RCCC/TFC bridge. Defaults leave NSCC and disabled CMS paths
    // unchanged. PDS retains all packet/connection identity validation.
    virtual bool accepts_credit_requests() const { return false; }
    virtual void work_posted(const Connection&,uint64_t payload_bytes) {}
    virtual std::optional<PDS_Nack_Codes> admit_receive(const Connection&,const PDStoNET_pkt&) { return {}; }
    virtual void handed_to_semantics(const Connection&,uint32_t psn) {}
    virtual void update_activity(const Connection&,bool established,bool unsent_data,
                                 bool unacknowledged_data,bool quiescing,uint64_t rto_ns) {}
    virtual bool has_credit_control(const Connection&) const { return false; }
    virtual std::optional<CreditControlMessage> take_credit_control(const Connection&) { return {}; }
    virtual void received_credit_control(const Connection&,const PDStoNET_pkt&) {}
    // Select the forward control path without charging data admission/bytes.
    virtual void decorate_control(const Connection& connection,PDStoNET_pkt& packet)=0;
    virtual void acknowledged(const Connection& connection,const PDStoNET_pkt& packet,
                               std::optional<NsccTransmitSample> sample)=0;
    virtual void negative_acknowledged(const Connection& connection,uint32_t nominal_size,
                               const PDStoNET_pkt& packet,std::optional<NsccTransmitSample> sample)=0;
    // Every valid NACK is observable, even if an earlier NACK already removed
    // that attempt's inflight contribution or the packet was a control.
    virtual void negative_acknowledgment_event(const Connection&,const PDStoNET_pkt&) {}
    virtual void inferred_loss(const Connection& connection,uint32_t nominal_size)=0;
    // A delivery ACK can beat a loss-marked retry waiting for admission. Undo
    // that provisional byte debit before retiring the request; no new packet
    // was sent, so this is accounting, not a congestion/window response.
    virtual void canceled_unsent_retry(const Connection& connection,uint32_t nominal_size)=0;
    virtual void received(const Connection& connection,const PDStoNET_pkt& packet,bool duplicate=false)=0;
    virtual void decorate_ack(const Connection& connection,uint32_t acknowledged_psn,PDStoNET_pkt& packet)=0;
    virtual void receive_cleared(const Connection& connection,uint32_t clear_through)=0;
    virtual void closed(const Connection& connection)=0;
};
} // namespace UET::CMS
