/*******************************************************************************
 * Copyright 2025 Soft UE Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

/**
 * @file             PDC.cpp
 * @brief            PDC.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This file implements the base PDC class providing core functionality for reliable data delivery.
 */


#include "PDC.hpp"
#include "PDC_RudInternals.hpp"
#include "../PDS_Manager/PDSManager.hpp"
#include <functional>
#include <algorithm>
#include <cstring>
#include <limits>

PDC::ResolveRxRequestPlacementFn PDC::resolve_rx_request_placement_{};
PDC::ResolveRxResponsePlacementFn PDC::resolve_rx_response_placement_{};
PDC::CompleteRxOperationFn PDC::complete_rx_operation_{};
PDC::CompleteRequestTerminalFn PDC::complete_request_terminal_{};
PDC::CompleteSenderTerminalFn PDC::complete_sender_terminal_{};
PDC::CompleteReadResponseTerminalFn PDC::complete_read_response_terminal_{};

namespace {

bool isLowValueCloseSuppressibleControl(cm_type type)
{
    switch (type) {
        case NOOP:
        case ACK_REQ:
        case CLR_CMD:
        case CLR_REQ:
        case SACK_CTRL:
            return true;
        default:
            return false;
    }
}

bool isTerminalOrClosingPdcState(pdc_state state)
{
    switch (state) {
        case ACK_WAIT:
        case CLOSE_ACK_WAIT:
        case QUIESCE:
        case CLOSED:
            return true;
        default:
            return false;
    }
}

bool isLowValueStandaloneControlPacket(const PDStoNET_pkt &pkt)
{
    if (pkt.PDS_type == RUOD_ack_header) {
        return true;
    }
    if (pkt.PDS_type != RUOD_cp_header) {
        return false;
    }
    switch (pkt.PDS_header.RUOD_cp_header.ctl_type) {
        case Noop:
        case ACK_req:
        case Clear_cmd:
        case Clear_req:
        case SACK:
        case Credit:
        case Credit_req:
            return true;
        default:
            return false;
    }
}

} // namespace
PDC::ResolvePostedRecvCreditsFn PDC::resolve_posted_recv_credits_{};

int64_t PDC::rudSackRefreshMs()
{
    const int64_t refresh = static_cast<int64_t>(Base_RTO) / 4;
    return std::max<int64_t>(15, std::min<int64_t>(50, refresh));
}

int64_t PDC::creditRefreshMs()
{
    const int64_t refresh = static_cast<int64_t>(Base_RTO) / 2;
    return std::max<int64_t>(50, std::min<int64_t>(200, refresh));
}

int64_t PDC::creditReqDelayMs()
{
    return creditRefreshMs();
}

bool PDC::isNewerCreditGen(uint16_t newer, uint16_t older)
{
    return static_cast<int16_t>(newer - older) > 0;
}

int PDC::controlPriority(cm_type type)
{
    switch (type) {
        case CLOSE_REQ:
        case CLR_CMD:
        case CLR_REQ:
            return 5;
        case CREDIT_REQ:
        case CREDIT:
        case SACK_CTRL:
            return 4;
        case CLOSE_CMD:
            return 3;
        case ACK_REQ:
            return 2;
        case NOOP:
            return 1;
        default:
            return 0;
    }
}

NackCtrlClass PDC::classifyNack(PDS_Nack_Codes nack_code)
{
    if (nack_code == UET_RCVR_INFER_LOSS) {
        return NackCtrlClass::LOSS_INFERENCE;
    }

    switch (nack_code) {
        case UET_INV_DPDCID:
        case UET_PDC_HDR_MISMATCH:
        case UET_CLOSING:
        case UET_CLOSING_IN_ERR:
        case UET_GTD_RESP_UNAVAIL:
        case UET_INVALID_SYN:
        case UET_PDC_MODE_MISMATCH:
        case UET_UNEXP_EVENT:
            return NackCtrlClass::FATAL_PROTOCOL;
        default:
            return NackCtrlClass::RESOURCE_RECOVERABLE;
    }
}

uint16_t PDC::computePostedRecvCredits(uint32_t job_id) const
{
    if (!resolve_posted_recv_credits_ || job_id == 0) {
        return 0;
    }
    return resolve_posted_recv_credits_(job_id, SPDCID, dst_fep);
}

uint16_t PDC::computeUnexpectedMsgCredits() const
{
    const RudResourceStats stats = getSharedRudResourceStats();
    const size_t available =
        (stats.max_unexpected_msgs > stats.unexpected_msgs_in_use)
            ? (stats.max_unexpected_msgs - stats.unexpected_msgs_in_use)
            : 0u;
    return static_cast<uint16_t>(std::min<size_t>(available, std::numeric_limits<uint16_t>::max()));
}

uint16_t PDC::computeUnexpectedByteCredits() const
{
    const RudResourceStats stats = getSharedRudResourceStats();
    const size_t units = stats.unexpected_bytes_available / kUnexpectedCreditUnitBytes;
    return static_cast<uint16_t>(std::min<size_t>(units, std::numeric_limits<uint16_t>::max()));
}

uint16_t PDC::computeUnexpectedMsgsInUse() const
{
    const RudResourceStats stats = getSharedRudResourceStats();
    return static_cast<uint16_t>(std::min<size_t>(stats.unexpected_msgs_in_use,
                                                  std::numeric_limits<uint16_t>::max()));
}

uint16_t PDC::computeBitmapBlocksAvailable() const
{
    const RudResourceStats stats = getSharedRudResourceStats();
    return static_cast<uint16_t>(std::min<size_t>(stats.bitmap_blocks_available,
                                                  std::numeric_limits<uint16_t>::max()));
}

uint16_t PDC::computeArrivalBlocksAvailable() const
{
    const RudResourceStats stats = getSharedRudResourceStats();
    return static_cast<uint16_t>(std::min<size_t>(stats.bitmap_blocks_available,
                                                  std::numeric_limits<uint16_t>::max()));
}

void PDC::observeReceiverJob(uint32_t job_id)
{
    if (job_id == 0) {
        return;
    }
    observed_receiver_jobs_.insert(job_id);
    auto &state = localCreditStateForJob(job_id);
    if (state.snapshot.job_id == 0) {
        state.snapshot.job_id = job_id;
        state.snapshot.byte_credit_shift = kUnexpectedCreditByteShift;
    }
}

LocalReceiverCreditState &PDC::localCreditStateForJob(uint32_t job_id)
{
    auto &state = local_receiver_credits_[job_id];
    if (state.snapshot.job_id == 0) {
        state.snapshot.job_id = job_id;
        state.snapshot.byte_credit_shift = kUnexpectedCreditByteShift;
    }
    return state;
}

PeerReceiverCreditState &PDC::peerCreditStateForJob(uint32_t job_id)
{
    return peer_receiver_credits_[job_id];
}

bool PDC::refreshLocalCreditForJob(uint32_t job_id, int64_t now_ms)
{
    if (job_id == 0) {
        return false;
    }
    observeReceiverJob(job_id);
    auto &state = localCreditStateForJob(job_id);
    const uint16_t posted_recv_credits = computePostedRecvCredits(job_id);
    const uint16_t unexpected_msg_credits = computeUnexpectedMsgCredits();
    const uint16_t unexpected_byte_credits = computeUnexpectedByteCredits();
    bool changed = false;
    if (state.snapshot.credit_gen == 0 ||
        state.snapshot.posted_recv_credits != posted_recv_credits ||
        state.snapshot.unexpected_msg_credits != unexpected_msg_credits ||
        state.snapshot.unexpected_byte_credits != unexpected_byte_credits) {
        state.snapshot.credit_gen = (state.snapshot.credit_gen == 0)
                                        ? 1
                                        : static_cast<uint16_t>(state.snapshot.credit_gen + 1);
        state.snapshot.posted_recv_credits = posted_recv_credits;
        state.snapshot.unexpected_msg_credits = unexpected_msg_credits;
        state.snapshot.unexpected_byte_credits = unexpected_byte_credits;
        state.snapshot.byte_credit_shift = kUnexpectedCreditByteShift;
        state.dirty = true;
        state.last_dirty_ms = now_ms;
        changed = true;
    }

    const uint16_t unexpected_msgs_in_use = computeUnexpectedMsgsInUse();
    const uint16_t unexpected_byte_credits_available = computeUnexpectedByteCredits();
    const uint16_t bitmap_blocks_available = computeBitmapBlocksAvailable();
    const uint16_t arrival_blocks_available = computeArrivalBlocksAvailable();
    if (unexpected_msgs_in_use != last_unexpected_msgs_in_use_ ||
        unexpected_byte_credits_available != last_receiver_pressure_unexpected_byte_credits_ ||
        bitmap_blocks_available != last_receiver_pressure_bitmap_blocks_available_ ||
        arrival_blocks_available != last_receiver_pressure_arrival_blocks_available_) {
        last_unexpected_msgs_in_use_ = unexpected_msgs_in_use;
        last_receiver_pressure_unexpected_byte_credits_ = unexpected_byte_credits_available;
        last_receiver_pressure_bitmap_blocks_available_ = bitmap_blocks_available;
        last_receiver_pressure_arrival_blocks_available_ = arrival_blocks_available;
        receiver_pressure_dirty_ = true;
    }

    pending_credit_job_id_ = job_id;
    local_credit_gen_ = state.snapshot.credit_gen;
    local_credit_last_sent_gen_ = state.snapshot.credit_gen;
    last_advertised_credit_ = state.snapshot.unexpected_msg_credits;
    local_credit_dirty_ = state.dirty;
    local_credit_dirty_since_ms_ = state.last_dirty_ms;
    last_credit_sent_ms_ = state.last_sent_ms;
    return changed;
}

bool PDC::hasDirtyLocalCreditJob() const
{
    for (const auto &entry : local_receiver_credits_) {
        if (entry.second.dirty) {
            return true;
        }
    }
    return false;
}

bool PDC::selectCreditJobForAck(uint32_t ack_job_id, int64_t now_ms, uint32_t *job_id_out)
{
    if (ack_job_id == 0) {
        return false;
    }
    refreshLocalCreditForJob(ack_job_id, now_ms);
    const auto it = local_receiver_credits_.find(ack_job_id);
    if (it == local_receiver_credits_.end()) {
        return false;
    }
    const auto &state = it->second;
    const bool due = state.dirty ||
                     state.last_sent_ms == 0 ||
                     ((now_ms - state.last_sent_ms) >= creditRefreshMs());
    if (!due) {
        return false;
    }
    if (job_id_out) {
        *job_id_out = ack_job_id;
    }
    return true;
}

bool PDC::selectStandaloneCreditJob(int64_t now_ms, uint32_t *job_id_out)
{
    if (pending_credit_job_id_ != 0 &&
        (pending_credit_reason_ == CreditControlReason::RESYNC_RESPONSE ||
         pending_credit_reason_ == CreditControlReason::REFRESH)) {
        refreshLocalCreditForJob(pending_credit_job_id_, now_ms);
        if (job_id_out) {
            *job_id_out = pending_credit_job_id_;
        }
        return true;
    }

    for (uint32_t job_id : observed_receiver_jobs_) {
        refreshLocalCreditForJob(job_id, now_ms);
        const auto it = local_receiver_credits_.find(job_id);
        if (it == local_receiver_credits_.end()) {
            continue;
        }
        const auto &state = it->second;
        if (state.dirty) {
            if (job_id_out) {
                *job_id_out = job_id;
            }
            return true;
        }
    }
    return false;
}

void PDC::encodeCreditSnapshotPayload(UET::PayloadHandle &payload,
                                      const ReceiverFlowCreditSnapshot &snapshot) const
{
    const PDS_RUOD_credit_cp_payload wire{
        snapshot.job_id,
        snapshot.credit_gen,
        snapshot.posted_recv_credits,
        snapshot.unexpected_msg_credits,
        snapshot.unexpected_byte_credits,
        snapshot.byte_credit_shift,
        snapshot.flags,
    };
    payload.allocate(sizeof(wire));
    if (payload.data()) {
        std::memcpy(payload.data(), &wire, sizeof(wire));
    }
}

bool PDC::decodeCreditSnapshotPayload(const UET::PayloadHandle &payload,
                                      ReceiverFlowCreditSnapshot *snapshot) const
{
    if (!snapshot || payload.size() < sizeof(PDS_RUOD_credit_cp_payload) || !payload.data()) {
        return false;
    }
    PDS_RUOD_credit_cp_payload wire{};
    std::memcpy(&wire, payload.data(), sizeof(wire));
    snapshot->job_id = wire.job_id;
    snapshot->credit_gen = wire.credit_gen;
    snapshot->posted_recv_credits = wire.posted_recv_credits;
    snapshot->unexpected_msg_credits = wire.unexpected_msg_credits;
    snapshot->unexpected_byte_credits = wire.unexpected_byte_credits;
    snapshot->byte_credit_shift = wire.byte_credit_shift;
    snapshot->flags = wire.flags;
    return true;
}

void PDC::encodeCreditReqPayload(UET::PayloadHandle &payload, uint32_t job_id, uint16_t last_seen_credit_gen) const
{
    const PDS_RUOD_credit_req_cp_payload wire{job_id, last_seen_credit_gen, 0};
    payload.allocate(sizeof(wire));
    if (payload.data()) {
        std::memcpy(payload.data(), &wire, sizeof(wire));
    }
}

bool PDC::decodeCreditReqPayload(const UET::PayloadHandle &payload,
                                 uint32_t *job_id,
                                 uint16_t *last_seen_credit_gen) const
{
    if (payload.size() < sizeof(PDS_RUOD_credit_req_cp_payload) || !payload.data()) {
        return false;
    }
    PDS_RUOD_credit_req_cp_payload wire{};
    std::memcpy(&wire, payload.data(), sizeof(wire));
    if (job_id) {
        *job_id = wire.job_id;
    }
    if (last_seen_credit_gen) {
        *last_seen_credit_gen = wire.last_seen_credit_gen;
    }
    return true;
}

void PDC::clearPendingSackControlIfMatching()
{
    if (gen_cm == SACK_CTRL) {
        gen_cm = NONE;
    }
}

bool PDC::maybeFillAckControlExt(PDStoNET_pkt *ack, int64_t now_ms, uint32_t ack_job_id)
{
    if (!ack) {
        return false;
    }

    ack->PDS_header.RUOD_ack_header.flags.x = 0;
    ack->ack_ctrl_ext = {};

    bool sack_present = false;
    bool credit_present = false;
    bool ackreq_hint_present = false;
    bool receiver_pressure_present = false;
    uint32_t credit_job_id = 0;
    uint32_t sack_base_psn = 0;
    uint32_t sack_bitmap = 0;
    uint32_t ackreq_psn = 0;

    if (isRudMode() && rud_sack_pending && (now_ms - rud_sack_first_ms) >= kRudSackDelayMs) {
        sack_bitmap = buildRudSackBitmap(&sack_base_psn);
        if (shouldSendSack(sack_base_psn, sack_bitmap, now_ms)) {
            sack_present = true;
        }
    }

    credit_present = selectCreditJobForAck(ack_job_id, now_ms, &credit_job_id);
    if (credit_present) {
        last_credit_ack_job_id_ = credit_job_id;
    }

    if (gen_cm == ACK_REQ) {
        ackreq_psn = clear_psn + 1;
        if (shouldSendAckReq(ackreq_psn, now_ms)) {
            ackreq_hint_present = true;
        }
    }

    if (receiver_pressure_dirty_ || local_credit_dirty_) {
        receiver_pressure_present = true;
    }

    if (!sack_present && !credit_present && !ackreq_hint_present && !receiver_pressure_present) {
        return false;
    }

    ack->PDS_header.RUOD_ack_header.flags.x = 1;
    ack->ack_ctrl_ext.prefix.version = 2;
    ack->ack_ctrl_ext.prefix.total_len = static_cast<uint8_t>(sizeof(PDS_RUOD_ack_ctrl_prefix));
    ack->ack_ctrl_ext.prefix.section_mask = 0;

    if (sack_present) {
        ack->ack_ctrl_ext.prefix.section_mask |= kAckCtrlExtSectionSack;
        ack->ack_ctrl_ext.prefix.total_len = static_cast<uint8_t>(
            ack->ack_ctrl_ext.prefix.total_len + sizeof(PDS_RUOD_ack_ctrl_sack_section));
        ack->ack_ctrl_ext.sack.sack_base_psn = sack_base_psn;
        ack->ack_ctrl_ext.sack.sack_bitmap = sack_bitmap;
        last_sack_base_psn_ = sack_base_psn;
        last_sack_bitmap_ = sack_bitmap;
        last_sack_ms_ = now_ms;
        rud_sack_pending = false;
        rud_sack_first_ms = 0;
        clearPendingSackControlIfMatching();
        noteRudPiggybackPromoted();
    }

    if (credit_present) {
        auto &state = localCreditStateForJob(credit_job_id);
        ack->ack_ctrl_ext.prefix.section_mask |= kAckCtrlExtSectionCredit;
        ack->ack_ctrl_ext.prefix.total_len = static_cast<uint8_t>(
            ack->ack_ctrl_ext.prefix.total_len + sizeof(PDS_RUOD_ack_ctrl_credit_section));
        ack->ack_ctrl_ext.credit.job_id = state.snapshot.job_id;
        ack->ack_ctrl_ext.credit.credit_gen = state.snapshot.credit_gen;
        ack->ack_ctrl_ext.credit.posted_recv_credits = state.snapshot.posted_recv_credits;
        ack->ack_ctrl_ext.credit.unexpected_msg_credits = state.snapshot.unexpected_msg_credits;
        ack->ack_ctrl_ext.credit.unexpected_byte_credits = state.snapshot.unexpected_byte_credits;
        ack->ack_ctrl_ext.credit.byte_credit_shift = state.snapshot.byte_credit_shift;
        ack->ack_ctrl_ext.credit.flags = state.snapshot.flags;
        state.dirty = false;
        state.last_sent_ms = now_ms;
        local_credit_last_sent_gen_ = state.snapshot.credit_gen;
        local_credit_gen_ = state.snapshot.credit_gen;
        last_advertised_credit_ = state.snapshot.unexpected_msg_credits;
        last_credit_sent_ms_ = state.last_sent_ms;
        local_credit_dirty_ = false;
        local_credit_dirty_since_ms_ = 0;
        if (gen_cm == CREDIT) {
            if (pending_credit_reason_ == CreditControlReason::REFRESH) {
                noteRudCreditRefreshSuppressed();
            }
            gen_cm = NONE;
            pending_credit_reason_ = CreditControlReason::NONE;
            pending_credit_job_id_ = 0;
        }
    }

    if (ackreq_hint_present) {
        ack->ack_ctrl_ext.prefix.section_mask |= kAckCtrlExtSectionAckReqHint;
        ack->ack_ctrl_ext.prefix.total_len = static_cast<uint8_t>(
            ack->ack_ctrl_ext.prefix.total_len + sizeof(PDS_RUOD_ack_ctrl_ackreq_hint_section));
        ack->ack_ctrl_ext.ackreq_hint.req_psn = ackreq_psn;
        noteAckReqSent(ackreq_psn, now_ms);
        if (gen_cm == ACK_REQ) {
            gen_cm = NONE;
        }
        noteRudPiggybackPromoted();
    }

    if (receiver_pressure_present) {
        ack->ack_ctrl_ext.prefix.section_mask |= kAckCtrlExtSectionReceiverPressure;
        ack->ack_ctrl_ext.prefix.total_len = static_cast<uint8_t>(
            ack->ack_ctrl_ext.prefix.total_len + sizeof(PDS_RUOD_ack_ctrl_receiver_pressure_section));
        ack->ack_ctrl_ext.receiver_pressure.unexpected_msgs_in_use = last_unexpected_msgs_in_use_;
        ack->ack_ctrl_ext.receiver_pressure.unexpected_byte_credits_available =
            last_receiver_pressure_unexpected_byte_credits_;
        ack->ack_ctrl_ext.receiver_pressure.bitmap_blocks_available =
            last_receiver_pressure_bitmap_blocks_available_;
        ack->ack_ctrl_ext.receiver_pressure.arrival_blocks_available =
            last_receiver_pressure_arrival_blocks_available_;
        last_pressure_sent_unexpected_msgs_in_use_ = last_unexpected_msgs_in_use_;
        receiver_pressure_dirty_ = false;
    }

    noteRudAckCtrlExtSent(sack_present, credit_present, ackreq_hint_present, receiver_pressure_present);
    return true;
}

void PDC::rxAckControlExt(const PDStoNET_pkt *pkt)
{
    if (!pkt || pkt->PDS_type != RUOD_ack_header || !pkt->PDS_header.RUOD_ack_header.flags.x) {
        return;
    }

    const auto &ext = pkt->ack_ctrl_ext;
    if (ext.prefix.version == 0 || ext.prefix.total_len < sizeof(PDS_RUOD_ack_ctrl_prefix)) {
        return;
    }

    if ((ext.prefix.section_mask & kAckCtrlExtSectionSack) != 0) {
        if (ext.sack.sack_base_psn > clear_psn) {
            const uint32_t cack_base = (ext.sack.sack_base_psn > 0) ? (ext.sack.sack_base_psn - 1) : 0;
            updateTxPsnTracker(ext.sack.sack_base_psn, 0, cack_base);
        }
        applyRudSack(ext.sack.sack_base_psn, ext.sack.sack_bitmap);
    }

    if ((ext.prefix.section_mask & kAckCtrlExtSectionCredit) != 0) {
        auto &peer = peerCreditStateForJob(ext.credit.job_id);
        if (!peer.valid || isNewerCreditGen(ext.credit.credit_gen, peer.credit_gen_seen)) {
            const bool had_pending_resync = (peer.blocked_since_ms != 0 && peer.last_credit_req_ms != 0);
            peer.valid = true;
            peer.credit_gen_seen = ext.credit.credit_gen;
            peer.posted_recv_credits = ext.credit.posted_recv_credits;
            peer.unexpected_msg_credits = ext.credit.unexpected_msg_credits;
            peer.unexpected_byte_credits = ext.credit.unexpected_byte_credits;
            peer.blocked_since_ms = 0;
            peer_credit_valid_ = peer.valid;
            peer_credit_gen_seen_ = peer.credit_gen_seen;
            peer_credit_available_ = static_cast<uint16_t>(peer.posted_recv_credits + peer.unexpected_msg_credits);
            credit_blocked_since_ms_ = 0;
            noteRudCreditUpdateRx();
            if (had_pending_resync) {
                noteRudCreditResyncSuccess();
            }
        } else {
            noteRudCreditStaleIgnored();
        }
    }
}

void PDC::rxCtrlCredit(PDStoNET_pkt *p)
{
    if (!p) {
        return;
    }
    ReceiverFlowCreditSnapshot snapshot{};
    if (!decodeCreditSnapshotPayload(p->SESpkt.payload, &snapshot)) {
        return;
    }
    auto &peer = peerCreditStateForJob(snapshot.job_id);
    if (!peer.valid || isNewerCreditGen(snapshot.credit_gen, peer.credit_gen_seen)) {
        const bool had_pending_resync = (peer.blocked_since_ms != 0 && peer.last_credit_req_ms != 0);
        peer.valid = true;
        peer.credit_gen_seen = snapshot.credit_gen;
        peer.posted_recv_credits = snapshot.posted_recv_credits;
        peer.unexpected_msg_credits = snapshot.unexpected_msg_credits;
        peer.unexpected_byte_credits = snapshot.unexpected_byte_credits;
        peer.blocked_since_ms = 0;
        peer_credit_valid_ = peer.valid;
        peer_credit_gen_seen_ = peer.credit_gen_seen;
        peer_credit_available_ = static_cast<uint16_t>(peer.posted_recv_credits + peer.unexpected_msg_credits);
        credit_blocked_since_ms_ = 0;
        noteRudCreditUpdateRx();
        if (had_pending_resync) {
            noteRudCreditResyncSuccess();
        }
    } else {
        noteRudCreditStaleIgnored();
    }
}

void PDC::rxCtrlCreditReq(PDStoNET_pkt *p)
{
    uint32_t job_id = 0;
    uint16_t last_seen_credit_gen = 0;
    if (!p || !decodeCreditReqPayload(p->SESpkt.payload, &job_id, &last_seen_credit_gen)) {
        return;
    }
    (void)last_seen_credit_gen;
    observeReceiverJob(job_id);
    refreshLocalCreditForJob(job_id, nowMs());
    pending_credit_job_id_ = job_id;
    pending_credit_reason_ = CreditControlReason::RESYNC_RESPONSE;
    requestControl(CREDIT);
}

bool PDC::hasCreditRefreshActivity() const
{
    bool any_blocked = credit_blocked_since_ms_ != 0;
    for (const auto &entry : peer_receiver_credits_) {
        if (entry.second.blocked_since_ms != 0) {
            any_blocked = true;
            break;
        }
    }
    return any_blocked ||
           !tx_req_q.empty() ||
           !tx_pkt_buffer.empty() ||
           !tx_ack_buffer.empty() ||
           !rx_pkt_q.empty();
}

bool PDC::maybeScheduleCreditRefresh(int64_t now_ms)
{
    if (!isRudMode() ||
        (state != ESTABLISHED && state != CREATING) ||
        !hasCreditRefreshActivity() ||
        credit_blocked_since_ms_ != 0) {
        return false;
    }
    if (pending_credit_reason_ == CreditControlReason::NONE && !hasDirtyLocalCreditJob()) {
        return false;
    }
    uint32_t credit_job_id = 0;
    if (!selectStandaloneCreditJob(now_ms, &credit_job_id)) {
        return false;
    }
    if (gen_cm != NONE && controlPriority(gen_cm) > controlPriority(CREDIT)) {
        noteRudCreditRefreshSuppressed();
        return false;
    }
    pending_credit_job_id_ = credit_job_id;
    pending_credit_reason_ = CreditControlReason::REFRESH;
    if (!requestControl(CREDIT)) {
        noteRudCreditRefreshSuppressed();
        pending_credit_reason_ = CreditControlReason::NONE;
        pending_credit_job_id_ = 0;
        return false;
    }
    return true;
}

bool PDC::canDispatchFrontReq(const PDS_PDC_req &req, int64_t now_ms)
{
    constexpr uint8_t kSendOpcode = 1;
    const uint32_t job_id = req.pkt.bth_header.Standard_Header.job_id;
    if (!isRudMode() || req.is_retry || !req.som || req.pkt.bth_type != Standard_Header ||
        req.pkt.bth_header.Standard_Header.opcode != kSendOpcode) {
        credit_blocked_since_ms_ = 0;
        return true;
    }

    auto &peer = peerCreditStateForJob(job_id);
    if (!peer.valid) {
        if (!peer.bootstrap_used) {
            peer.bootstrap_used = true;
            bootstrap_credit_used_ = true;
            return true;
        }
        if (peer.blocked_since_ms == 0) {
            peer.blocked_since_ms = now_ms;
            credit_blocked_since_ms_ = now_ms;
            noteRudCreditGateBlocked();
        }
        if ((now_ms - peer.blocked_since_ms) >= creditReqDelayMs() &&
            (peer.last_credit_req_ms == 0 || (now_ms - peer.last_credit_req_ms) >= creditReqDelayMs())) {
            if (peer.last_credit_req_ms != 0) {
                noteRudCreditResyncTimeout();
            }
            pending_credit_req_job_id_ = job_id;
            requestControl(CREDIT_REQ);
            peer.last_credit_req_ms = now_ms;
            last_credit_req_ms_ = now_ms;
        }
        return false;
    }

    const uint32_t req_len = req.pkt.bth_header.Standard_Header.request_length;
    const uint16_t byte_units = static_cast<uint16_t>(
        std::min<uint32_t>(
            std::numeric_limits<uint16_t>::max(),
            req_len == 0 ? 0u : ((req_len + kUnexpectedCreditUnitBytes - 1) / kUnexpectedCreditUnitBytes)));
    if (peer.posted_recv_credits > 0) {
        --peer.posted_recv_credits;
    } else if (peer.unexpected_msg_credits > 0 && peer.unexpected_byte_credits >= byte_units) {
        --peer.unexpected_msg_credits;
        peer.unexpected_byte_credits = static_cast<uint16_t>(peer.unexpected_byte_credits - byte_units);
    } else {
        if (peer.blocked_since_ms == 0) {
            peer.blocked_since_ms = now_ms;
            credit_blocked_since_ms_ = now_ms;
            noteRudCreditGateBlocked();
        }
        if ((now_ms - peer.blocked_since_ms) >= creditReqDelayMs() &&
            (peer.last_credit_req_ms == 0 || (now_ms - peer.last_credit_req_ms) >= creditReqDelayMs())) {
            if (peer.last_credit_req_ms != 0) {
                noteRudCreditResyncTimeout();
            }
            pending_credit_req_job_id_ = job_id;
            requestControl(CREDIT_REQ);
            peer.last_credit_req_ms = now_ms;
            last_credit_req_ms_ = now_ms;
        }
        return false;
    }

    peer.valid = true;
    peer_credit_valid_ = true;
    peer_credit_gen_seen_ = peer.credit_gen_seen;
    peer_credit_available_ = static_cast<uint16_t>(peer.posted_recv_credits + peer.unexpected_msg_credits);
    peer.blocked_since_ms = 0;
    credit_blocked_since_ms_ = 0;
    return true;
}

bool PDC::shouldSendAckReq(uint32_t req_psn, int64_t now_ms)
{
    if (last_ack_req_ms_ != 0 &&
        last_ack_req_psn_ == req_psn &&
        (now_ms - last_ack_req_ms_) < kRudAckReqMinIntervalMs) {
        return false;
    }
    return true;
}

void PDC::noteAckReqSent(uint32_t req_psn, int64_t now_ms)
{
    last_ack_req_psn_ = req_psn;
    last_ack_req_ms_ = now_ms;
    noteRudCtrlAckReqSent();
}

bool PDC::shouldSendSack(uint32_t base_psn, uint32_t bitmap, int64_t now_ms)
{
    if (last_sack_ms_ != 0 &&
        last_sack_base_psn_ == base_psn &&
        last_sack_bitmap_ == bitmap &&
        (now_ms - last_sack_ms_) < rudSackRefreshMs()) {
        return false;
    }
    return true;
}

void PDC::noteSackSent(uint32_t base_psn, uint32_t bitmap, int64_t now_ms)
{
    last_sack_base_psn_ = base_psn;
    last_sack_bitmap_ = bitmap;
    last_sack_ms_ = now_ms;
    noteRudCtrlSackSent();
}

bool PDC::shouldSendRecoverableNack(PDS_Nack_Codes nack_code,
                                    uint32_t nack_psn,
                                    uint32_t payload,
                                    int64_t now_ms)
{
    if (last_resource_nack_ms_ != 0 &&
        last_resource_nack_code_ == nack_code &&
        last_resource_nack_psn_ == nack_psn &&
        last_resource_nack_payload_ == payload &&
        (now_ms - last_resource_nack_ms_) < kRecoverableNackMinIntervalMs) {
        return false;
    }
    return true;
}

void PDC::noteGapNackSuppressed()
{
    noteRudCtrlGapNackSuppressed();
    noteRudCtrlNackSuppressed();
    noteRudCtrlNackSuppressedByClass(static_cast<uint8_t>(NackCtrlClass::LOSS_INFERENCE));
}

bool PDC::shouldSendGapNack(int64_t now_ms)
{
    const int64_t next_deadline =
        (rud_gap_last_nack_ms_ == 0) ? (rud_gap_first_ms + kRudGapDelayMs)
                                     : (rud_gap_last_nack_ms_ + rud_gap_retry_interval_ms_);
    if (now_ms < next_deadline) {
        if (!rud_gap_suppressed_in_window_) {
            noteGapNackSuppressed();
            rud_gap_suppressed_in_window_ = true;
        }
        return false;
    }

    return true;
}

bool PDC::selectRudReadResponseGap(uint32_t *gap_psn_out, int64_t now_ms)
{
    uint32_t selected_gap_psn = 0;
    for (const auto &entry : rud_rx_messages_) {
        const auto &key = entry.first;
        const auto &ctx = entry.second;
        if (key.opcode != kReadOpcode || ctx.completed || ctx.failed) {
            continue;
        }
        if (ctx.base_psn == 0 || ctx.expected_chunks == 0 || ctx.ePSN >= ctx.expected_chunks) {
            continue;
        }
        if (ctx.chunks_done <= ctx.ePSN) {
            continue;
        }
        const uint32_t gap_psn = ctx.base_psn + ctx.ePSN;
        if (selected_gap_psn == 0 || gap_psn < selected_gap_psn) {
            selected_gap_psn = gap_psn;
        }
    }

    if (selected_gap_psn == 0) {
        rud_rsp_gap_psn_ = 0;
        rud_rsp_gap_first_ms_ = 0;
        rud_rsp_gap_last_nack_ms_ = 0;
        rud_rsp_gap_retry_interval_ms_ = kRudGapDelayMs;
        rud_rsp_gap_suppressed_in_window_ = false;
        return false;
    }

    if (rud_rsp_gap_psn_ != selected_gap_psn) {
        rud_rsp_gap_psn_ = selected_gap_psn;
        rud_rsp_gap_first_ms_ = now_ms;
        rud_rsp_gap_last_nack_ms_ = 0;
        rud_rsp_gap_retry_interval_ms_ = kRudGapDelayMs;
        rud_rsp_gap_suppressed_in_window_ = false;
    }

    if (gap_psn_out) {
        *gap_psn_out = selected_gap_psn;
    }
    return true;
}

void PDC::noteGapNackSent(int64_t now_ms)
{
    rud_gap_last_nack_ms_ = now_ms;
    rud_gap_retry_interval_ms_ =
        std::min<int64_t>(kRudGapMaxIntervalMs, std::max<int64_t>(kRudGapDelayMs, rud_gap_retry_interval_ms_ * 2));
    rud_gap_suppressed_in_window_ = false;
    noteRudCtrlGapNackSent();
}

bool PDC::requestControl(cm_type type)
{
    if (type == NONE) {
        return false;
    }
    if (isLowValueCloseSuppressibleControl(type) &&
        (closing || close_error || isTerminalOrClosingPdcState(state))) {
        if (gen_cm == type) {
            gen_cm = NONE;
        }
        return false;
    }
    if (gen_cm == NONE || controlPriority(type) >= controlPriority(gen_cm)) {
        gen_cm = type;
        return true;
    }
    return false;
}

bool PDC::tryConsumeBudgetClassB(int64_t now_ms)
{
    refillCtrlBudget(now_ms);
    if (rud_ctrl_budget_tokens_ <= 0) {
        noteRudCtrlBudgetDeferredByClass(true);
        return false;
    }
    rud_ctrl_budget_tokens_ = std::max(0, rud_ctrl_budget_tokens_ - kRudCtrlBudgetClassBCost);
    return true;
}

bool PDC::tryConsumeBudgetClassC(int64_t now_ms)
{
    refillCtrlBudget(now_ms);
    if (rud_ctrl_budget_tokens_ < kRudCtrlBudgetClassCCost) {
        noteRudCtrlBudgetDeferredByClass(false);
        return false;
    }
    rud_ctrl_budget_tokens_ -= kRudCtrlBudgetClassCCost;
    return true;
}

void PDC::refillCtrlBudget(int64_t now_ms)
{
    if (rud_ctrl_budget_last_refill_ms_ == 0) {
        rud_ctrl_budget_last_refill_ms_ = now_ms;
        return;
    }
    const int64_t elapsed = now_ms - rud_ctrl_budget_last_refill_ms_;
    if (elapsed < kRudCtrlBudgetWindowMs) {
        return;
    }
    const int64_t windows = elapsed / kRudCtrlBudgetWindowMs;
    rud_ctrl_budget_tokens_ = std::min(kRudCtrlBudgetCapacity,
                                       rud_ctrl_budget_tokens_ + static_cast<int>(windows) * kRudCtrlBudgetCapacity);
    rud_ctrl_budget_last_refill_ms_ += windows * kRudCtrlBudgetWindowMs;
}

bool PDC::tryConsumeCtrlBudget(cm_type type, int64_t now_ms)
{
    switch (type) {
        case CREDIT:
        case CREDIT_REQ:
            return tryConsumeBudgetClassB(now_ms);
        case ACK_REQ:
        case SACK_CTRL:
            return tryConsumeBudgetClassC(now_ms);
        default:
            return true;
    }
}

bool PDC::tryConsumeGapNackBudget(int64_t now_ms)
{
    return tryConsumeBudgetClassC(now_ms);
}

bool PDC::consumeSkipCtrlEmitOnce()
{
    if (!skip_ctrl_emit_once_) {
        return false;
    }
    skip_ctrl_emit_once_ = false;
    return true;
}

/**
 * @brief PDC constructor 
 * @details Initializes PDC with default parameters and sets up timer callback
 */
PDC::PDC()
    : rto_timer_([this](uint32_t psn) {
          {
              std::lock_guard<std::mutex> lock(queue_mutex_);
              rto_pkt_q.push(psn);
          }

          LOG_WARN("RTOTimer::timeout_callback",
                   formatLogMessage("Packet timeout - PSN: " + std::to_string(psn)));

          std::cout << getCurrentTimestamp() << formatLogMessage("Packet timeout, added to retransmission queue - PSN: ")
                    << psn << std::endl;
      }),
      mode(RUD),                    
      SPDCID(0),                    
      DPDCID(0),                    
      unack_cnt(0),                 
      allACK(true),                 
      open_msg(0),                  
      SYN(false),                   
      MPR(Default_MPR),             
      ACK_GEN_COUNT(0),             
      start_psn(1000),              
      tx_cur_psn(start_psn),        
      clear_psn(start_psn - 1),     
      rx_cur_psn(start_psn - 1),    
      cack_psn(start_psn - 1),      
      rx_clear_psn(start_psn - 1),  
      pause_pdc(false),             
      gen_cm(NONE),                 
      gen_ack(false),               
      trim(false),                  
      rx_error(false),              
      error_chk(OPEN),              
      close_error(false),           
      closing(false),               
      pdc_close_timer(0),           
      state(CLOSED),                
      public_net_queue(nullptr),    
      public_ses_req_queue(nullptr),
      public_ses_rsp_queue(nullptr),
      public_close_queue(nullptr)  
{
    markActivity();
    LOG_INFO("PDC::PDC", formatLogMessage("PDC constructor called - initialization completed"));
    std::cout << getCurrentTimestamp() << formatLogMessage("PDC constructor completed initialization") << std::endl;
}

/**
 * @brief PDC destructor 
 * @details Cleans up all resources including timers, maps, and queues
 */
PDC::~PDC()
{
    LOG_INFO("PDC::~PDC", formatLogMessage("PDC destructor called - starting resource cleanup"));
    std::cout << getCurrentTimestamp() << formatLogMessage("PDC destructor starting resource cleanup") << std::endl;

    
    rto_timer_.stop();

    // Clean up all timer resources
    clearAllPacketTimers();
    terminalizeOutstandingRequests(SenderTerminalReason::TEARDOWN_ORPHAN);
    terminalizeOutstandingSenderRetries(SenderTerminalReason::TEARDOWN_ORPHAN);
    terminalizeOutstandingReadResponses(ReadResponseTerminalReason::TEARDOWN_ORPHAN);
    // Ensure RUD receive state and shared resources are released even when a
    // connection only reaches object teardown rather than an explicit close path.
    freePDC();

    
    public_net_queue = nullptr;
    public_ses_req_queue = nullptr;
    public_ses_rsp_queue = nullptr;
    public_close_queue = nullptr;

    LOG_INFO("PDC::~PDC", formatLogMessage("PDC destructor completed - all resources cleaned up"));
}

void PDC::setRxCallbacks(ResolveRxRequestPlacementFn req_cb,
                         ResolveRxResponsePlacementFn rsp_cb,
                         CompleteRxOperationFn complete_cb,
                         CompleteRequestTerminalFn request_terminal_cb,
                         CompleteSenderTerminalFn terminal_cb,
                         CompleteReadResponseTerminalFn read_terminal_cb,
                         ResolvePostedRecvCreditsFn posted_recv_cb)
{
    resolve_rx_request_placement_ = std::move(req_cb);
    resolve_rx_response_placement_ = std::move(rsp_cb);
    complete_rx_operation_ = std::move(complete_cb);
    complete_request_terminal_ = std::move(request_terminal_cb);
    complete_sender_terminal_ = std::move(terminal_cb);
    complete_read_response_terminal_ = std::move(read_terminal_cb);
    resolve_posted_recv_credits_ = std::move(posted_recv_cb);
}

bool PDC::isRudMode() const
{
    return mode == RUD;
}

bool PDC::hasRxCallbacks()
{
    return static_cast<bool>(resolve_rx_request_placement_) &&
           static_cast<bool>(resolve_rx_response_placement_) &&
           static_cast<bool>(complete_rx_operation_) &&
           static_cast<bool>(complete_request_terminal_) &&
           static_cast<bool>(complete_sender_terminal_) &&
           static_cast<bool>(complete_read_response_terminal_) &&
           static_cast<bool>(resolve_posted_recv_credits_);
}

pdc_mode PDC::packetMode(const PDStoNET_pkt *pkt) const
{
    if (!pkt) {
        return mode;
    }
    if (pkt->PDS_type == RUOD_req_header) {
        return pkt->PDS_header.RUOD_req_header.type == RUD_REQ ? RUD : ROD;
    }
    if (pkt->PDS_type == RUOD_cp_header) {
        return pkt->PDS_header.RUOD_cp_header.flags.isrod ? ROD : RUD;
    }
    return mode;
}

bool PDC::packetModeMatches(const PDStoNET_pkt *pkt) const
{
    return packetMode(pkt) == mode;
}

void PDC::advanceRudRxFrontier()
{
    while (rud_rx_ooo_psns.erase(rx_cur_psn + 1) != 0) {
        ++rx_cur_psn;
    }
    refreshRudGapState();
}

void PDC::refreshRudGapState()
{
    if (!isRudMode() || rud_rx_ooo_psns.empty()) {
        rud_gap_pending = false;
        rud_gap_psn = 0;
        rud_gap_first_ms = 0;
        rud_gap_last_nack_ms_ = 0;
        rud_gap_retry_interval_ms_ = kRudGapDelayMs;
        rud_gap_suppressed_in_window_ = false;
        return;
    }

    const uint32_t expected = rx_cur_psn + 1;
    const uint32_t first_ooo = *rud_rx_ooo_psns.begin();
    if (first_ooo > expected) {
        if (!rud_gap_pending || rud_gap_psn != expected) {
            rud_gap_pending = true;
            rud_gap_psn = expected;
            rud_gap_first_ms = nowMs();
            rud_gap_last_nack_ms_ = 0;
            rud_gap_retry_interval_ms_ = kRudGapDelayMs;
            rud_gap_suppressed_in_window_ = false;
        }
        return;
    }

    rud_gap_pending = false;
    rud_gap_psn = 0;
    rud_gap_first_ms = 0;
    rud_gap_last_nack_ms_ = 0;
    rud_gap_retry_interval_ms_ = kRudGapDelayMs;
    rud_gap_suppressed_in_window_ = false;
}

uint32_t PDC::buildRudSackBitmap(uint32_t *base_psn_out) const
{
    const uint32_t base_psn = rx_cur_psn;
    uint32_t bitmap = 0;
    for (uint32_t psn : rud_rx_ooo_psns) {
        if (psn <= base_psn) {
            continue;
        }
        const uint32_t delta = psn - base_psn;
        if (delta == 0 || delta > 32) {
            continue;
        }
        bitmap |= (1u << (delta - 1));
    }
    if (base_psn_out) {
        *base_psn_out = base_psn;
    }
    return bitmap;
}

void PDC::noteRudSackPending()
{
    if (!isRudMode()) {
        return;
    }
    rud_sack_pending = true;
    if (rud_sack_first_ms == 0) {
        rud_sack_first_ms = nowMs();
    }
}

void PDC::noteRudGapPending()
{
    refreshRudGapState();
}

void PDC::maybeTriggerRudControl()
{
    if (!isRudMode()) {
        return;
    }

    reapUnexpectedPartialState();

    const int64_t now = nowMs();
    for (uint32_t job_id : observed_receiver_jobs_) {
        refreshLocalCreditForJob(job_id, now);
    }
    if (rud_sack_pending && (now - rud_sack_first_ms) >= kRudSackDelayMs) {
        requestControl(SACK_CTRL);
    }

    maybeScheduleCreditRefresh(now);

    bool sent_gap_nack = false;
    if (rud_gap_pending && shouldSendGapNack(now)) {
        if (!tryConsumeGapNackBudget(now)) {
            if (!rud_gap_suppressed_in_window_) {
                noteGapNackSuppressed();
                rud_gap_suppressed_in_window_ = true;
            }
            return;
        }
        noteGapNackSent(now);
        sendNack(0, rud_gap_psn, UET_RCVR_INFER_LOSS, rx_cur_psn + 1, nullptr);
        skip_ctrl_emit_once_ = (gen_cm != NONE);
        sent_gap_nack = true;
    }

    uint32_t rsp_gap_psn = 0;
    if (!sent_gap_nack && selectRudReadResponseGap(&rsp_gap_psn, now)) {
        const int64_t next_deadline =
            (rud_rsp_gap_last_nack_ms_ == 0) ? (rud_rsp_gap_first_ms_ + kRudGapDelayMs)
                                             : (rud_rsp_gap_last_nack_ms_ + rud_rsp_gap_retry_interval_ms_);
        if (now >= next_deadline) {
            if (!tryConsumeGapNackBudget(now)) {
                if (!rud_rsp_gap_suppressed_in_window_) {
                    noteGapNackSuppressed();
                    rud_rsp_gap_suppressed_in_window_ = true;
                }
                return;
            }
            rud_rsp_gap_last_nack_ms_ = now;
            rud_rsp_gap_retry_interval_ms_ = std::min<int64_t>(
                kRudGapMaxIntervalMs,
                std::max<int64_t>(kRudGapDelayMs, rud_rsp_gap_retry_interval_ms_ * 2));
            rud_rsp_gap_suppressed_in_window_ = false;
            noteRudCtrlGapNackSent();
            sendNack(0, rsp_gap_psn, UET_RCVR_INFER_LOSS, rsp_gap_psn, nullptr);
            skip_ctrl_emit_once_ = (gen_cm != NONE);
        } else if (!rud_rsp_gap_suppressed_in_window_) {
            noteGapNackSuppressed();
            rud_rsp_gap_suppressed_in_window_ = true;
        }
    }
}

void PDC::applyRudSack(uint32_t base_psn, uint32_t bitmap)
{
    for (uint32_t bit = 0; bit < 32; ++bit) {
        if ((bitmap & (1u << bit)) == 0) {
            continue;
        }
        const uint32_t psn = base_psn + 1 + bit;
        if (psn > clear_psn) {
            rud_tx_sacked_psns.insert(psn);
        }
    }

    for (auto it = rud_tx_sacked_psns.begin(); it != rud_tx_sacked_psns.end();) {
        if (*it <= clear_psn) {
            it = rud_tx_sacked_psns.erase(it);
        } else {
            ++it;
        }
    }
}

bool PDC::handleRudRxRequest(PDStoNET_pkt *pkt)
{
    if (!pkt || !isRudMode()) {
        return false;
    }

    if (!packetModeMatches(pkt)) {
        sendNack(pkt->PDS_header.RUOD_req_header.flags.retx,
                 pkt->PDS_header.RUOD_req_header.psn,
                 UET_PDC_MODE_MISMATCH,
                 0,
                 nullptr);
        return true;
    }

    const uint32_t psn = pkt->PDS_header.RUOD_req_header.psn;
    const uint32_t window_end = rx_cur_psn + static_cast<uint32_t>(std::max(MPR, 1));

    if (psn < rx_clear_psn) {
        noteRudSackPending();
        return true;
    }

    if (psn <= rx_cur_psn || rud_rx_ooo_psns.count(psn) != 0) {
        if (pkt->PDS_header.RUOD_req_header.flags.ar) {
            sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, rx_cur_psn, nullptr, false,
                    pkt->SESpkt.bth_header.Standard_Header.job_id);
        } else {
            noteRudSackPending();
        }
        return true;
    }

    if (psn > window_end) {
        sendNack(pkt->PDS_header.RUOD_req_header.flags.retx,
                 psn,
                 UET_PSN_OOR_WINDOW,
                 rx_cur_psn + 1,
                 nullptr);
        return true;
    }

    const bool in_order = (psn == rx_cur_psn + 1);
    const uint16_t handle = processRxReq(pkt);
    RX_pkt_meta meta = rx_pkt_map.at(handle);
    updateRxPsnTracker(&meta);

    if (!in_order) {
        rud_rx_ooo_psns.insert(psn);
        noteRudGapPending();
        noteRudSackPending();
    } else {
        advanceRudRxFrontier();
        if (!rud_rx_ooo_psns.empty()) {
            noteRudSackPending();
        }
    }

    if (pkt->PDS_header.RUOD_req_header.flags.ar) {
        sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, rx_cur_psn, nullptr, false,
                pkt->SESpkt.bth_header.Standard_Header.job_id);
    }

    if (!directPlaceRudWrite(pkt, handle, meta) &&
        !directPlaceRudSend(pkt, handle, meta)) {
        fwdReq2SES(handle, meta, &pkt->SESpkt);
    }
    return true;
}

/**
 * @brief Process received request
 * @param pkt Received network packet
 * @return Processing result handle
 */
uint16_t PDC::processRxReq(PDStoNET_pkt *pkt)
{
    markActivity();
    RX_pkt_meta meta = {};
    meta.type = pkt->PDS_header.RUOD_req_header.type;
    meta.next_hdr = pkt->PDS_header.RUOD_req_header.next_hdr;
    meta.spdcid = pkt->PDS_header.RUOD_req_header.spdcid;
    meta.src_fep = pkt->src_fep;
    meta.psn = pkt->PDS_header.RUOD_req_header.psn;
    meta.clear_psn = meta.psn - pkt->PDS_header.RUOD_req_header.clear_psn_off;
    meta.syn = pkt->PDS_header.RUOD_req_header.flags.syn;
    meta.retx = pkt->PDS_header.RUOD_req_header.flags.retx;
    meta.ar = pkt->PDS_header.RUOD_req_header.flags.ar;
    meta.som = pkt->SESpkt.bth_header.Standard_Header.som;
    // RUOD/SES request length on the wire:
    // - PDS only sees the PDStoNET_pkt object
    // - payload bytes are now carried in pkt->SESpkt.payload (filled by SES send path + UDP shim)
    // - PDC's RX bookkeeping should reflect the actual bytes delivered with this packet
    meta.payload_len = static_cast<uint16_t>(pkt->SESpkt.payload.size());

    uint16_t handle = setRXhandle(meta.psn, meta.spdcid);
    rx_pkt_map.insert({handle, meta});
    return handle;
}

/**
 * @brief Update TX PSN tracker 
 * @details Updates current transmission PSN and handles flow control
 */
void PDC::updateTxPsnTracker(){
    ////FUNCTION_LOG_ENTRY();

    
    std::stringstream before_state;
    before_state << "Before update state - tx_cur_psn: " << tx_cur_psn
                << ", unack_cnt: " << unack_cnt
                << ", MPR: " << MPR
                << ", pause_pdc: " << (pause_pdc ? "true" : "false");
    LOG_DEBUG(__FUNCTION__, before_state.str());

    
    tx_cur_psn = tx_cur_psn + 1;
    
    unack_cnt++;

    std::cout << getCurrentTimestamp() << "I_PDC update TX PSN - tx_cur_psn: " << tx_cur_psn
            << ", unack_cnt: " << unack_cnt << std::endl;

    if ((tx_cur_psn - clear_psn) >= (unsigned)(MPR / 2) && state == ESTABLISHED)
    {
        requestControl(ACK_REQ);
        std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Need to send ACK Request, current psn: " << tx_cur_psn << ", clear_psn: " << clear_psn << std::endl;
    }
    else if ((unack_cnt >= MPR))
    {
        requestControl(ACK_REQ);
        pause_pdc = true;
    }

    
    std::stringstream after_state;
    after_state << "Updated state - tx_cur_psn: " << tx_cur_psn
                << ", unack_cnt: " << unack_cnt
                << ", pause_pdc: " << (pause_pdc ? "true" : "false");
    LOG_INFO(__FUNCTION__, after_state.str());

    ////FUNCTION_LOG_EXIT();
}

/**
 * @brief Update TX PSN tracker with parameters
 * @param psn Packet sequence number
 * @param ack_req_flag ACK request flag
 * @param cack_psn Cumulative ACK PSN
 */
void PDC::updateTxPsnTracker(uint32_t psn, uint8_t ack_req_flag, uint32_t cack_psn){
    //FUNCTION_LOG_ENTRY();

    
    std::stringstream params;
    params << "Update TX PSN tracker - psn: " << psn
            << ", ack_req_flag: " << (int)ack_req_flag
            << ", cack_psn: " << cack_psn
            << ", Current clear_psn: " << clear_psn
            << ", Current unack_cnt: " << unack_cnt;
    LOG_INFO(__FUNCTION__, params.str());

    std::cout << getCurrentTimestamp() << "I_PDCUpdate TX PSN tracker - psn: " << psn
            << ", clear_psn: " << clear_psn << ", unack_cnt: " << unack_cnt << std::endl;

    if (unack_cnt < 0) {
        LOG_WARN(__FUNCTION__,
                 formatLogMessage("Detected negative unack_cnt before ACK processing, clamping to zero"));
        unack_cnt = 0;
    }

    if(psn > clear_psn + 1 && psn > cack_psn + 1) {
        requestControl(ACK_REQ);
        std::cout << getCurrentTimestamp() << "Need to send ACK Request, tx_cur_psn: " << tx_cur_psn << ", clear_psn: " << clear_psn << std::endl;
        LOG_WARN(__FUNCTION__, "Detected ACK loss, set generate ACK Request");
    }
    else if(psn > clear_psn){
        uint32_t old_unack_cnt = unack_cnt;
        const int acked = static_cast<int>(psn - clear_psn);
        unack_cnt = std::max(0, unack_cnt - acked);
        
        for (uint32_t i = clear_psn; i < psn; i++)
        {
            if (tx_pkt_map.count(i))
            {
                if(USE_RTO) stopPacketTimer(i);  
                tx_pkt_map.erase(i);
                tx_pkt_buffer.erase(i);
            }
        }   
        clear_psn = psn;
        pause_pdc = false;
        for (auto it = rud_tx_sacked_psns.begin(); it != rud_tx_sacked_psns.end();) {
            if (*it <= clear_psn) {
                it = rud_tx_sacked_psns.erase(it);
            } else {
                ++it;
            }
        }
        
        std::stringstream update_info;
        update_info << "PSN acknowledgment update - old unack_cnt: " << old_unack_cnt
                    << ", acked: " << acked
                    << ", New unack_cnt: " << unack_cnt
                    << ", New clear_psn: " << clear_psn
                    << ", pause_pdc: false";
        LOG_INFO(__FUNCTION__, update_info.str());
    
        
        
        // 条件：
        bool tx_queue_empty = false;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            tx_queue_empty = tx_pkt_q.empty();
        }
        if(tx_queue_empty && unack_cnt == 0 && (ack_req_flag == 0x01)) {
            requestControl(CLR_CMD);
            std::cout << getCurrentTimestamp() << ", clear_psn: " << clear_psn << ", ack_req_flag: " << (int)ack_req_flag << std::endl;
            LOG_INFO(__FUNCTION__, "Clear Command conditions met, set generate Clear Command");
        }
    }

    //FUNCTION_LOG_EXIT();
}

/**
 * @brief Update RX PSN tracker
 * @param meta Received packet metadata
 */
void PDC::updateRxPsnTracker(RX_pkt_meta *meta){
    //FUNCTION_LOG_ENTRY();

    if(!meta) {
        LOG_ERROR(__FUNCTION__, "接收包元数据指针为空");
        //FUNCTION_LOG_EXIT();
        return;
    }

    uint32_t psn = meta->psn;
    uint32_t cpsn = meta->clear_psn;
    rx_clear_psn = std::max(rx_clear_psn, meta->clear_psn); 
    
    std::stringstream before_state;
    before_state << "Before update state - rx_cur_psn: " << rx_cur_psn
                    << ", cack_psn: " << cack_psn
                    << ", Received psn: " << psn
                    << ", Received clear_psn: " << cpsn;
    LOG_DEBUG(__FUNCTION__, before_state.str());

    if(psn == rx_cur_psn + 1){
        rx_cur_psn = psn;
        std::cout << getCurrentTimestamp() << "I_PDC update RX PSN - rx_cur_psn: " << rx_cur_psn << std::endl;
        LOG_INFO(__FUNCTION__, "Receive PSN sequential update");
    }

    if(cpsn > cack_psn){
        uint32_t old_cack = cack_psn;
        
        for (uint32_t i = cack_psn; i < cpsn; i++)
        {
            if (tx_ack_buffer.count(i))
            {
                tx_pkt_map.erase(i);
                tx_ack_buffer.erase(i);
            }
        }
        cack_psn = cpsn;    
        std::stringstream cack_update;
        cack_update << "Cumulative ACK PSN update - old cack_psn: " << old_cack << ", New cack_psn: " << cack_psn;
        LOG_INFO(__FUNCTION__, cack_update.str());
        std::cout << getCurrentTimestamp() << "I_PDC update cumulative ACK PSN - cack_psn: " << cack_psn << std::endl;
    }

    if(Enb_ACK_Per_Pkt && meta->som == false){
        uint16_t pl = meta->payload_len;
        if(pl >= ACK_Gen_Min_Pkt_Add) ACK_GEN_COUNT += pl;
        else ACK_GEN_COUNT += ACK_Gen_Min_Pkt_Add;
        
        if(ACK_GEN_COUNT >= ACK_Gen_Trigger){
            gen_ack = true;
            ACK_GEN_COUNT = 0;
            LOG_INFO(__FUNCTION__, "ACK generation threshold reached, set generate ACK flag");
        std::cout << getCurrentTimestamp() << "I_PDC reached ACK generation threshold, preparing to generate ACK" << std::endl;
        }
    }

//FUNCTION_LOG_EXIT();
}

/**
 * @brief Update RX PSN tracker with guaranteed delivery
 * @param meta Received packet metadata
 * @param gtd_del Guaranteed delivery flag
 */
void PDC::updateRxPsnTracker(RX_pkt_meta *meta, bool gtd_del)
{
    if (!gtd_del)
    {
        cack_psn = meta->psn;
    }
    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] update_rx_psn_tracker,rx_cur_psn:" << rx_cur_psn << "cack_psn:" << cack_psn << std::endl;
    if (rx_cur_psn == cack_psn)
        allACK = true;
    else
        allACK = false;
}


/**
 * @brief Retransmit specified PSN packet
 * @param psn Packet sequence number
 */
void PDC::reTx(uint32_t psn){
    if (rud_tx_sacked_psns.count(psn) != 0) {
        return;
    }
    PDStoNET_pkt p{};
    if (tx_pkt_buffer.count(psn) != 0) {
        p = tx_pkt_buffer.at(psn);
        p.PDS_header.RUOD_req_header.flags.retx = 1;
    } else if (tx_ack_buffer.count(psn) != 0) {
        p = tx_ack_buffer.at(psn);
        if (p.PDS_type == RUOD_ack_header) {
            p.PDS_header.RUOD_ack_header.flags.retx = 1;
        } else if (p.PDS_type == RUOD_cp_header) {
            p.PDS_header.RUOD_cp_header.flags.retx = 1;
        }
    } else {
        return;
    }
    if (public_net_queue) {
        public_net_queue->push(p);
    } else {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        tx_pkt_q.push(p);
    }
}

/**
 * @brief Handle transmission timeout
 * @param psn Timeout packet sequence number
 */
void PDC::txRto(uint32_t psn){
    if (rud_tx_sacked_psns.count(psn) != 0) {
        return;
    }
    auto meta_it = tx_pkt_map.find(psn);
    if (meta_it == tx_pkt_map.end()) {
        LOG_DEBUG(__FUNCTION__,
                  "Skip stale RTO callback for missing PSN: " + std::to_string(psn));
        return;
    }

    PDStoNET_pkt p{};
    bool have_packet = false;
    if (tx_pkt_buffer.count(psn) != 0) {
        p = tx_pkt_buffer.at(psn);
        p.PDS_header.RUOD_req_header.flags.retx = 1;
        have_packet = true;
    } else if (tx_ack_buffer.count(psn) != 0) {
        p = tx_ack_buffer.at(psn);
        if (p.PDS_type == RUOD_ack_header) {
            p.PDS_header.RUOD_ack_header.flags.retx = 1;
        } else if (p.PDS_type == RUOD_cp_header) {
            p.PDS_header.RUOD_cp_header.flags.retx = 1;
        }
        have_packet = true;
    }

    if (!have_packet) {
        LOG_DEBUG(__FUNCTION__,
                  "Skip stale RTO callback for PSN without packet buffer: " + std::to_string(psn));
        tx_pkt_map.erase(meta_it);
        return;
    }

    TX_pkt_meta meta = meta_it->second;
    if(meta.retry_cnt < Max_RTO_Retx_Cnt){
        meta.retry_cnt++;
        meta.rto = Base_RTO * (1 << meta.retry_cnt);
        tx_pkt_map[psn] = meta; 
        std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Packet retransmission - PSN: " << psn
                << ", retry_cnt: " << meta.retry_cnt
                << ", new_rto22: " << meta.rto << std::endl;
        
        startPacketTimer(psn, meta.retry_cnt);

        std::stringstream retry_info;
        retry_info << "Retransmit packet - PSN: " << psn
                    << ", retry_cnt: " << meta.retry_cnt
                    << ", new_rto: " << meta.rto;
        LOG_INFO(__FUNCTION__, retry_info.str());
        if (public_net_queue) {
            public_net_queue->push(p);
        } else {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            tx_pkt_q.push(p);
        }
    } else {
        bool suppress_close_error = false;
        if (meta.job_id != 0) {
            const SenderTerminalKey request_key{meta.job_id, meta.msg_id, meta.dst_fep};
            const ReadResponseTerminalKey read_key{meta.job_id, meta.msg_id, meta.dst_fep};
            suppress_close_error =
                (request_terminalized_keys_.count(request_key) != 0) ||
                (meta.is_read_response_data && read_response_terminalized_keys_.count(read_key) != 0);
        } else {
            auto ack_it = tx_ack_buffer.find(psn);
            if (ack_it != tx_ack_buffer.end() && isLowValueStandaloneControlPacket(ack_it->second)) {
                suppress_close_error = true;
            }
            auto pkt_it = tx_pkt_buffer.find(psn);
            if (!suppress_close_error &&
                pkt_it != tx_pkt_buffer.end() &&
                isLowValueStandaloneControlPacket(pkt_it->second)) {
                suppress_close_error = true;
            }
        }
        if (suppress_close_error) {
            if (USE_RTO) {
                stopPacketTimer(psn);
            }
            tx_pkt_map.erase(psn);
            tx_pkt_buffer.erase(psn);
            tx_ack_buffer.erase(psn);
            markActivity();
            LOG_INFO(__FUNCTION__,
                     "Suppress close_error escalation for low-value/terminalized timeout PSN=" +
                         std::to_string(psn));
            return;
        }
        LOG_ERROR(__FUNCTION__, "重传次数超限,设置关闭错误标志");
        emitRequestTerminalCompletion(meta, SenderTerminalReason::RTO_EXHAUSTED);
        if (meta.is_read_response_data) {
            emitReadResponseTerminalCompletion(meta, ReadResponseTerminalReason::RTO_EXHAUSTED);
        } else {
            emitSenderTerminalCompletion(meta, SenderTerminalReason::RTO_EXHAUSTED);
        }
        close_error = true;
        
        open_msg = 0;
        unack_cnt = 0;
    } 
}


/**
 * @brief Free PDC resources 
 * @details Clears all buffers and queues
 */
void PDC::freePDC()
{
    terminalizeOutstandingRequests(SenderTerminalReason::CLOSE_RESET);
    terminalizeOutstandingSenderRetries(SenderTerminalReason::CLOSE_RESET);
    terminalizeOutstandingReadResponses(ReadResponseTerminalReason::CLOSE_RESET);
    {
        std::lock_guard<std::mutex> lock(g_request_tx_registry_mu);
        for (auto it = g_request_tx_registry.begin(); it != g_request_tx_registry.end();) {
            if (it->owner == this) {
                it = g_request_tx_registry.erase(it);
            } else {
                ++it;
            }
        }
    }
    tx_pkt_map.clear();
    rx_pkt_map.clear();
    tx_pkt_buffer.clear();
    tx_ack_buffer.clear();
    resetRudState();

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        while (!tx_pkt_q.empty()) tx_pkt_q.pop();
        while (!tx_req_q.empty()) tx_req_q.pop();
        while (!tx_rsp_q.empty()) tx_rsp_q.pop();
        while (!rx_pkt_q.empty()) rx_pkt_q.pop();
        while (!rx_req_pkt_q.empty()) rx_req_pkt_q.pop();
        while (!rx_rsp_pkt_q.empty()) rx_rsp_pkt_q.pop();
        while (!rto_pkt_q.empty()) rto_pkt_q.pop();
    }

    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] PDC resources released" << std::endl;
}

/**
 * @brief Send NACK response
 * @param rsp Response packet
 */
void PDC::txNack(SES_PDC_rsp *rsp)
{
    if(!rsp) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入响应指针为空"));
        return;
    }

    
    if(rx_pkt_map.find(rsp->rx_pkt_handle) == rx_pkt_map.end()) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("未找到对应句柄的接收包元数据"));
        return;
    }

    RX_pkt_meta meta = rx_pkt_map.at(rsp->rx_pkt_handle);

    
    std::stringstream nack_info;
    nack_info << "SES layer requests to send NACK - handle: " << rsp->rx_pkt_handle
                << ", PSN: " << meta.psn
                << ", ses_nack: " << (rsp->ses_nack ? "true" : "false");
    LOG_WARN(__FUNCTION__, formatLogMessage(nack_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("Send SES NACK - PSN: ") << meta.psn << std::endl;

    
    PDS_Nack_Codes nack_code = static_cast<PDS_Nack_Codes>(rsp->nack_payload.nack_code);
    if (static_cast<NackCode>(rsp->nack_payload.nack_code) == NackCode::RESOURCE) {
        nack_code = UET_NO_BITMAP;
    }

    sendNack(0, meta.psn, nack_code, 0, &rsp->pkt);

    
    rx_pkt_map.erase(rsp->rx_pkt_handle);
}
/**
 * @brief Handle control packet generation and transmission
 * @details Processes and sends various control message types
 */
void PDC::txCtrl(){
    if(state != ESTABLISHED && state != CREATING) {
        if (isLowValueCloseSuppressibleControl(gen_cm) || isTerminalOrClosingPdcState(state)) {
            gen_cm = NONE;
            ctrl_tx_deferred_ = false;
        }
        std::cout << "PDC state does not allow processing control packet, current state: " << state << std::endl;
        return;
    }
    else{
        PDStoNET_pkt p = {};
        bool emitted = true;
        ctrl_tx_deferred_ = false;
        // Set basic control packet properties
        p.PDS_type = RUOD_cp_header;
        p.dst_fep = dst_fep;
        p.src_fep = src_fep;
        p.PDS_header.RUOD_cp_header.type = CP;
        p.PDS_header.RUOD_cp_header.flags.syn = 0;
        p.PDS_header.RUOD_cp_header.flags.retx = 0;         
        p.PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
        switch (gen_cm)
        {
        case NOOP:
            sendCtrlNoop(&p);
            break;
        case ACK_REQ:
            emitted = sendCtrlAckReq(&p);
            break;
        case CLR_CMD:
            sendCtrlClearCmd(&p);
            break;
        case CLR_REQ:
            sendCtrlClearReq(&p);
            break;
        case CLOSE_REQ:
            sendCtrlCloseReq(&p);
            break;
        case CREDIT:
            emitted = sendCtrlCredit(&p);
            break;
        case CREDIT_REQ:
            emitted = sendCtrlCreditReq(&p);
            break;
        case SACK_CTRL:
            emitted = sendCtrlSack(&p);
            break;
        case NEGOTIATION:
            sendCtrlNegotiation(&p);
            break;
        default:
            LOG_ERROR(__FUNCTION__, formatLogMessage("未知控制消息类型"));
        }
        if (!emitted) {
            if (!ctrl_tx_deferred_) {
                gen_cm = NONE;
            }
            return;
        }
        const uint32_t ctrl_psn = p.PDS_header.RUOD_cp_header.psn;
        if(ctrl_psn != 0){
            tx_pkt_buffer.insert(std::make_pair(ctrl_psn, p)); 
            if(USE_RTO){
                startPacketTimer(ctrl_psn, 0); 
            }
        }
        if (public_net_queue) {
            public_net_queue->push(p);
        } else {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            tx_pkt_q.push(p);
        }
        gen_cm = NONE;
    }
}
/**
 * @brief Forward request to SES layer
 * @param handle Request handle
 * @param meta Packet metadata
 * @param pkt Packet data
 */
void PDC::fwdReq2SES(uint16_t handle, RX_pkt_meta meta, SEStoPDS_pkt *pkt)
{
    if(!pkt) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("SES packet pointer is null"));
        return;
    }

    
    std::stringstream fwd_info;
    fwd_info << "Forward request to SES layer - handle: " << handle
                << ", PSN: " << meta.psn
                << ", SPDCID: " << meta.spdcid
                << ", next_hdr: " << meta.next_hdr
                << ", payload_len: " << meta.payload_len;
    LOG_INFO(__FUNCTION__, formatLogMessage(fwd_info.str()));

    PDC_SES_req req;
    req.PDCID = SPDCID;                     
    req.rx_pkt_handle = handle;
    req.mode = static_cast<uint8_t>(mode);
    req.pkt = *pkt;
    req.pkt_len = meta.payload_len;
    req.next_hdr = meta.next_hdr;
    req.src_fep = meta.src_fep;
    req.orig_psn = meta.psn;
    req.orig_pdcid = meta.spdcid;

    if (public_ses_req_queue) {
        public_ses_req_queue->push(req);
    } else {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        rx_req_pkt_q.push(req);
    }
    if (meta.som) {
        incPending();
    } else {
        markActivity();
    }
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Request added to SES layer receive queue"));

    std::cout << getCurrentTimestamp() << formatLogMessage("Forward to SES - handle: ") << handle
                << ", PSN: " << meta.psn << std::endl;
}

/**
 * @brief Forward response to SES layer
 * @param pkt Response packet pointer
 */
void PDC::fwdRsp2SES(const PDStoNET_pkt *pkt)
{
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Forward response to SES layer"));
    if (!pkt) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("Response packet pointer is null"));
        return;
    }
    markActivity();
    PDC_SES_rsp rsp;
    rsp.PDCID = SPDCID;                     
    rsp.mode = static_cast<uint8_t>(mode);
    rsp.rx_pkt_handle = cacheResponseHandle(pkt);
    rsp.pkt = pkt->SESpkt;                         // 响应包内容
    rsp.pkt_len = static_cast<uint16_t>(pkt->SESpkt.payload.size());
    rsp.src_fep = pkt->src_fep;

    if (mode == RUD &&
        rsp.pkt.bth_type == Semantic_Response_Header) {
        const auto &hdr = rsp.pkt.bth_header.Semantic_Response_Header;
        if (hdr.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
            hdr.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK)) {
            request_terminalized_keys_.insert(SenderTerminalKey{hdr.job_id, hdr.message_id, dst_fep});
        }
    }

    if (public_ses_rsp_queue) {
        LOG_DEBUG(__FUNCTION__, formatLogMessage("加入公共队列"));
        public_ses_rsp_queue->push(rsp);
        LOG_DEBUG(__FUNCTION__, formatLogMessage("响应已加入公共队列"));
    } else {
        LOG_DEBUG(__FUNCTION__, formatLogMessage("加入本地队列"));
        std::lock_guard<std::mutex> lock(queue_mutex_);
        rx_rsp_pkt_q.push(rsp);
        LOG_DEBUG(__FUNCTION__, formatLogMessage("响应已加入本地队列"));
    }
}

/**
 * @brief Check reception error
 * @param pkt Received packet
 */
void PDC::chkRxError(PDStoNET_pkt *pkt)
{
    uint32_t psn = pkt->PDS_header.RUOD_req_header.psn;
    const uint32_t window_end = rx_cur_psn + static_cast<uint32_t>(std::max(MPR, 1));

    if (isRudMode() && psn > rx_cur_psn + 1 && psn <= window_end) {
        std::cout << getCurrentTimestamp() << formatLogMessage("RUD窗口内乱序包，接收并等待补洞") << std::endl;
        error_chk = OOO_ACCEPT;
    } else if (psn > rx_cur_psn + 1) {
        std::cout << getCurrentTimestamp() << formatLogMessage("收到预期外的psn") << std::endl;
        if (pkt->PDS_header.RUOD_req_header.flags.syn == 1)
            error_chk = INV_SYN;
        else
            error_chk = OOO;
    } else if (psn < rx_clear_psn) {
        std::cout << getCurrentTimestamp() << formatLogMessage("PSN less than clear_psn, discard") << std::endl;
        error_chk = DROP;
    } else if (psn >= rx_clear_psn && psn <= rx_cur_psn) {
        std::cout << getCurrentTimestamp() << formatLogMessage("重复包") << std::endl;
        error_chk = ACK_ERROR;
    } else {
        std::cout << getCurrentTimestamp() << formatLogMessage("包正常") << std::endl;
        error_chk = OPEN;
    }
}

/**
 * @brief Process NOOP control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlNoop(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    } else if (p->PDS_header.RUOD_cp_header.flags.ar) {
        sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, p->PDS_header.RUOD_cp_header.psn, nullptr, false);
        return;
    } else {
        return;
    }
}

/**
 * @brief Process ACK_req control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlAckReq(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }

    uint32_t req_psn = p->PDS_header.RUOD_cp_header.psn;
    // For prototypes, an ACK request may arrive before this PDC instance has fully
    // learned the peer DPDCID via the SYN handshake. Ensure ACKs we generate here
    // are routable back to the requester.
    if (DPDCID == 0) {
        DPDCID = p->PDS_header.RUOD_cp_header.spdcid;
    }
    if (DPDCID != p->PDS_header.RUOD_cp_header.spdcid) {
        DPDCID = p->PDS_header.RUOD_cp_header.spdcid;
    }

    std::stringstream req_info;
    req_info << "Receive ACK Request - Request PSN: " << req_psn
                << ", SPDCID: " << p->PDS_header.RUOD_cp_header.spdcid
                << ", DPDCID: " << p->PDS_header.RUOD_cp_header.dpdcid;
    LOG_INFO(__FUNCTION__, formatLogMessage(req_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("rx_ctrl_ack_req - Request PSN: ") << req_psn << std::endl;

    // Semantics for prototype:
    // - ACK_REQ is used as a "please tell me what you've received" probe to advance TX window.
    // - Respond with our current in-order receive PSN (rx_cur_psn), not only the requested PSN.
    //   This allows the sender to advance clear_psn by more than 1 and avoids ACK_REQ storms.
    if (req_psn > rx_cur_psn) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("Requested PSN exceeds current receive PSN range"));
        sendNack(0, req_psn, UET_PKT_NOT_RCVD, rx_cur_psn + 1, nullptr);
        return;
    }

    const uint32_t ack_psn = rx_cur_psn;
    LOG_INFO(__FUNCTION__, formatLogMessage("ACK_REQ response uses rx_cur_psn=" + std::to_string(ack_psn)));
    std::cout << getCurrentTimestamp() << formatLogMessage("Construct ACK response, PSN: ") << ack_psn << std::endl;
    sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, ack_psn, nullptr, false);
}

void PDC::rxCtrlSack(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }

    const uint32_t base_psn = p->PDS_header.RUOD_cp_header.payload;
    const uint32_t bitmap = loadSackBitmap(p->SESpkt.payload);
    if (base_psn > clear_psn) {
        const uint32_t cack_base = (base_psn > 0) ? (base_psn - 1) : 0;
        updateTxPsnTracker(base_psn, 0, cack_base);
    }
    applyRudSack(base_psn, bitmap);
    LOG_INFO(__FUNCTION__,
             formatLogMessage("Receive SACK control - base_psn: " + std::to_string(base_psn) +
                              ", bitmap: 0x" + std::to_string(bitmap)));
}

/**
 * @brief Process Clear_cmd control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlClearCmd(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }

    uint32_t clear_psn_cmd = p->PDS_header.RUOD_cp_header.payload;

    std::stringstream cmd_info;
    cmd_info << "Receive Clear Command - CLEAR_PSN: " << clear_psn_cmd
                << ", SPDCID: " << p->PDS_header.RUOD_cp_header.spdcid
                << ", DPDCID: " << p->PDS_header.RUOD_cp_header.dpdcid;
    LOG_INFO(__FUNCTION__, formatLogMessage(cmd_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("rx_ctrl_clear_cmd - CLEAR_PSN: ") << clear_psn_cmd << std::endl;

    if (clear_psn_cmd > cack_psn) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("PSN in Clear Command exceeds current cumulative acknowledgment PSN"));
        std::cout << getCurrentTimestamp() << formatLogMessage("Invalid CLEAR_PSN: ") << clear_psn_cmd
                    << ", Current cack_psn: " << cack_psn << std::endl;
        return;
    }

    std::cout << getCurrentTimestamp() << formatLogMessage("Clear ACK buffer, range: ") << cack_psn
                << " 到 " << clear_psn_cmd << std::endl;

    auto it = tx_ack_buffer.begin();
    while (it != tx_ack_buffer.end()) {
        if (it->first <= clear_psn_cmd) {
            std::cout << getCurrentTimestamp() << formatLogMessage("Delete PSN from ACK buffer: ") << it->first << std::endl;
            LOG_DEBUG(__FUNCTION__, formatLogMessage("Delete PSN from ACK buffer: " + std::to_string(it->first)));
            tx_pkt_map.erase(it->first);
            it = tx_ack_buffer.erase(it);
        } else {
            ++it;
        }
    }

    if (clear_psn_cmd > clear_psn) {
        const int cleared = static_cast<int>(clear_psn_cmd - clear_psn);
        const int old_unack_cnt = unack_cnt;
        unack_cnt = std::max(0, unack_cnt - cleared);
        clear_psn = clear_psn_cmd;
        LOG_INFO(__FUNCTION__,
                 formatLogMessage("Clear Command advanced clear_psn, old unack_cnt=" +
                                  std::to_string(old_unack_cnt) +
                                  ", cleared=" + std::to_string(cleared) +
                                  ", new unack_cnt=" + std::to_string(unack_cnt)));
    }

    std::stringstream state_info;
    state_info << "Clear Command processing complete - Clear range: 0 到 " << clear_psn_cmd
                << ", Remaining ACK buffer size: " << tx_ack_buffer.size();
    LOG_INFO(__FUNCTION__, formatLogMessage(state_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("Clear Command处理完成，Remaining ACK buffer size: ")
                << tx_ack_buffer.size() << std::endl;

    if (p->PDS_header.RUOD_cp_header.flags.ar) {
        LOG_WARN(__FUNCTION__, formatLogMessage("Clear Command包含AR标志，这可能是协议违规"));
        std::cout << getCurrentTimestamp() << formatLogMessage("Warning: Clear Command set AR flag") << std::endl;
    }
}

/**
 * @brief Process Clear_req control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlClearReq(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }

    uint32_t req_clear_psn = p->PDS_header.RUOD_cp_header.payload;

    std::stringstream req_info;
    req_info << "Receive Clear Request - Request clear PSN: " << req_clear_psn
                << ", SPDCID: " << p->PDS_header.RUOD_cp_header.spdcid
                << ", DPDCID: " << p->PDS_header.RUOD_cp_header.dpdcid;
    LOG_INFO(__FUNCTION__, formatLogMessage(req_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("rx_ctrl_clear_req - Request clear PSN: ") << req_clear_psn << std::endl;

    if (req_clear_psn > clear_psn) {
        LOG_WARN(__FUNCTION__, formatLogMessage("Requested clear PSN exceeds current clear_psn range"));
        std::cout << getCurrentTimestamp() << formatLogMessage("Request clear PSN ") << req_clear_psn
                    << " exceeds current clear_psn " << clear_psn << std::endl;
    }

    bool has_resources_to_clear = false;

    for (auto it = tx_pkt_buffer.begin(); it != tx_pkt_buffer.end(); ++it) {
        if (it->first <= req_clear_psn) {
            has_resources_to_clear = true;
            break;
        }
    }

    if (!has_resources_to_clear) {
        for (auto it = tx_pkt_map.begin(); it != tx_pkt_map.end(); ++it) {
            if (it->first <= req_clear_psn) {
                has_resources_to_clear = true;
                break;
            }
        }
    }

    if (has_resources_to_clear) {
        std::cout << getCurrentTimestamp() << formatLogMessage("Clear send buffer, range: 0 到 ") << req_clear_psn << std::endl;
        LOG_INFO(__FUNCTION__, formatLogMessage("清除发送缓冲区中的过期包"));

        auto buf_it = tx_pkt_buffer.begin();
        while (buf_it != tx_pkt_buffer.end()) {
            if (buf_it->first <= req_clear_psn) {
                std::cout << getCurrentTimestamp() << formatLogMessage("清除发送包PSN: ") << buf_it->first << std::endl;
                if(USE_RTO) stopPacketTimer(buf_it->first);  // 停止计时器
                buf_it = tx_pkt_buffer.erase(buf_it);
            } else {
                ++buf_it;
            }
        }

        auto meta_it = tx_pkt_map.begin();
        while (meta_it != tx_pkt_map.end()) {
            if (meta_it->first <= req_clear_psn) {
                meta_it = tx_pkt_map.erase(meta_it);
            } else {
                ++meta_it;
            }
        }

        if (req_clear_psn > clear_psn) {
            const int cleared = static_cast<int>(req_clear_psn - clear_psn);
            const int old_unack_cnt = unack_cnt;
            unack_cnt = std::max(0, unack_cnt - cleared);
            clear_psn = req_clear_psn;
            std::cout << getCurrentTimestamp() << formatLogMessage("Update clear_psn to: ") << clear_psn << std::endl;
            LOG_INFO(__FUNCTION__, formatLogMessage("Update clear_psn to: " + std::to_string(clear_psn)));
            LOG_INFO(__FUNCTION__,
                     formatLogMessage("Clear Request advanced clear_psn, old unack_cnt=" +
                                      std::to_string(old_unack_cnt) +
                                      ", cleared=" + std::to_string(cleared) +
                                      ", new unack_cnt=" + std::to_string(unack_cnt)));
        }
    }

    std::cout << getCurrentTimestamp() << formatLogMessage("Generate Clear Command response") << std::endl;
    LOG_INFO(__FUNCTION__, formatLogMessage("生成Clear Command作为清除请求的响应"));

    if (!(closing || close_error || isTerminalOrClosingPdcState(state))) {
        requestControl(CLR_CMD);
    } else {
        LOG_INFO(__FUNCTION__, formatLogMessage("Skip CLR_CMD response because PDC is closing/terminal"));
    }

    std::stringstream completion_info;
    completion_info << "Clear Request processing complete - Clear PSN: " << req_clear_psn
                    << ", Current clear_psn: " << clear_psn
                    << ", Remaining send buffer size: " << tx_pkt_buffer.size()
                    << ", Remaining metadata size: " << tx_pkt_map.size();
    LOG_INFO(__FUNCTION__, formatLogMessage(completion_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("Clear Request processing complete, remaining send buffer: ")
                << tx_pkt_buffer.size() << ", 元数据: " << tx_pkt_map.size() << std::endl;
}
/**
 * @brief Send close request packet // Send close request包
 */
void PDC::sendCloseReq()
{
    PDStoNET_pkt pkt = {};  
    pkt.PDS_type = RUOD_cp_header;
    pkt.PDS_header.RUOD_cp_header.type = CP;
    pkt.PDS_header.RUOD_cp_header.ctl_type = 0x3;
    pkt.PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    pkt.PDS_header.RUOD_cp_header.flags.retx = 0;
    pkt.PDS_header.RUOD_cp_header.psn = tx_cur_psn;
    pkt.PDS_header.RUOD_cp_header.spdcid = SPDCID;
    pkt.PDS_header.RUOD_cp_header.dpdcid = DPDCID;

    TX_pkt_meta meta;
    meta.tx_pkt_handle = 0;
    meta.rto = Base_RTO;
    meta.retry_cnt = 0;

    tx_ack_buffer.insert(std::make_pair(tx_cur_psn, pkt));
    tx_pkt_map.insert(std::make_pair(tx_cur_psn, meta));

    if(USE_RTO){
       startPacketTimer(tx_cur_psn, 0);
    }

    updateTxPsnTracker();
    

    if (public_net_queue) {
        public_net_queue->push(pkt);
    } else {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        tx_pkt_q.push(pkt);
    }
    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Send close request" << std::endl;
}    
/**
 * @brief Send close acknowledgment packet // 发送关闭确认包
 */
void PDC::sendCloseAck()
{
    PDStoNET_pkt pkt = {};  
    pkt.dst_fep = dst_fep;
    pkt.src_fep = src_fep;
    pkt.PDS_type = RUOD_ack_header;
    pkt.PDS_header.RUOD_ack_header.type = ACK;
    pkt.PDS_header.RUOD_ack_header.next_hdr = UET_HDR_NONE;
    // ACK wire format: ack_psn = cack_psn + ack_psn_off.
    // Keep it simple/robust for the prototype: report "ACK for rx_cur_psn" using an in-order base.
    const uint32_t cack_base = (rx_cur_psn > 0) ? (rx_cur_psn - 1) : 0;
    pkt.PDS_header.RUOD_ack_header.cack_psn = cack_base;
    pkt.PDS_header.RUOD_ack_header.ack_psn_off = rx_cur_psn - cack_base;
    pkt.PDS_header.RUOD_ack_header.dpdcid = DPDCID;
    pkt.PDS_header.RUOD_ack_header.spdcid = SPDCID;


    if (public_net_queue) {
        public_net_queue->push(pkt);
        LOG_INFO(__FUNCTION__, formatLogMessage("发送关闭确认到公共队列"));
    } else {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        tx_pkt_q.push(pkt);
        LOG_INFO(__FUNCTION__, formatLogMessage("发送关闭确认到本地队列"));
    }
}    
/**
 * @brief Send Noop control packet 
 * @param p Control packet pointer // 控制包指针
 */
void PDC::sendCtrlNoop(PDStoNET_pkt *p){
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Noop control packet"));
    p->PDS_header.RUOD_cp_header.ctl_type = Noop;
    p->PDS_header.RUOD_cp_header.psn = setPsn();         
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.flags.ar = 1;           
    p->PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    p->PDS_header.RUOD_cp_header.flags.syn = SYN;        
    p->PDS_header.RUOD_cp_header.payload = 0;            
    if(!SYN)p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    else{
        p->PDS_header.RUOD_cp_header.pdc_info = 0;      
        p->PDS_header.RUOD_req_header.psn_off = p->PDS_header.RUOD_cp_header.psn - start_psn;
    }

    updateTxPsnTracker();
}
/**
 * @brief Send ACK Request control packet 
 * @param p Control packet pointer // 控制包指针
 */
bool PDC::sendCtrlAckReq(PDStoNET_pkt *p){
    LOG_INFO(__FUNCTION__, formatLogMessage("Send ACK Request control packet"));
    LOG_INFO(__FUNCTION__, formatLogMessage("ACK Request control packet DPDCID: " + std::to_string(DPDCID)));

    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("ACK_REQ control packet pointer is null"));
        return false;
    }

    const uint32_t req_psn = clear_psn + 1;
    const int64_t now_ms = nowMs();
    if (!shouldSendAckReq(req_psn, now_ms)) {
        noteRudCtrlAckReqSuppressed();
        LOG_DEBUG(__FUNCTION__,
                  formatLogMessage("Suppress duplicate ACK_REQ for req_psn=" + std::to_string(req_psn)));
        return false;
    }
    if (!tryConsumeCtrlBudget(ACK_REQ, now_ms)) {
        noteRudCtrlAckReqSuppressed();
        ctrl_tx_deferred_ = true;
        return false;
    }

    p->PDS_header.RUOD_cp_header.ctl_type = ACK_req;
    p->PDS_header.RUOD_cp_header.psn = req_psn;
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    p->PDS_header.RUOD_cp_header.flags.ar = 1;        
    p->PDS_header.RUOD_cp_header.payload = tx_pkt_buffer.count(req_psn)
        ? tx_pkt_buffer.at(req_psn).SESpkt.bth_header.Standard_Header.msg_id
        : 0;
    noteAckReqSent(req_psn, now_ms);
    noteRudStandaloneFallbackSent();
    return true;
}

/**
 * @brief Send Clear Command control packet 
 * @param p Control packet pointer // 控制包指针
 */
void PDC::sendCtrlClearCmd(PDStoNET_pkt *p){
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Clear Command control packet"));
    p->PDS_header.RUOD_cp_header.ctl_type = Clear_cmd;
    p->PDS_header.RUOD_cp_header.psn = 0;                
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    p->PDS_header.RUOD_cp_header.flags.ar = 0;           
    p->PDS_header.RUOD_cp_header.payload = clear_psn;    
}

/**
 * @brief Send Clear Request control packet 
 * @param p Control packet pointer // 控制包指针
 */
void PDC::sendCtrlClearReq(PDStoNET_pkt *p){
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Clear Request control packet"));
    p->PDS_header.RUOD_cp_header.ctl_type = Clear_req;
    p->PDS_header.RUOD_cp_header.psn = 0;                
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    p->PDS_header.RUOD_cp_header.flags.ar = 0;           
    p->PDS_header.RUOD_cp_header.payload = cack_psn + 1;    
}
/**
 * @brief Send Close_req control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::sendCtrlCloseReq(PDStoNET_pkt *p)
{
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Close_req control packet"));
    p->PDS_header.RUOD_cp_header.ctl_type = Close_req;
    p->PDS_header.RUOD_cp_header.flags.ar = 1;
    p->PDS_header.RUOD_cp_header.psn = tx_cur_psn; 
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    p->PDS_header.RUOD_cp_header.pdc_info = 0;
    p->PDS_header.RUOD_cp_header.payload = 0x0;
    updateTxPsnTracker();
}

/**
 * @brief Send Credit control message 
 * @param p Data packet to process // 需要处理的数据包
 * @warning TODO: We need to study credit-based flow control 
 */
bool PDC::sendCtrlCredit(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return false;
    }

    const int64_t now_ms = nowMs();
    uint32_t credit_job_id = 0;
    if (!selectStandaloneCreditJob(now_ms, &credit_job_id)) {
        return false;
    }
    refreshLocalCreditForJob(credit_job_id, now_ms);
    auto &state = localCreditStateForJob(credit_job_id);
    if (!tryConsumeCtrlBudget(CREDIT, now_ms)) {
        ctrl_tx_deferred_ = true;
        if (pending_credit_reason_ == CreditControlReason::REFRESH) {
            noteRudCreditRefreshSuppressed();
        }
        return false;
    }
    p->PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    p->PDS_header.RUOD_cp_header.ctl_type = Credit;
    p->PDS_header.RUOD_cp_header.flags.ar = 0;
    p->PDS_header.RUOD_cp_header.flags.syn = 0;
    p->PDS_header.RUOD_cp_header.psn = 0;
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.pdc_info = 0;
    p->PDS_header.RUOD_cp_header.payload = 0;
    encodeCreditSnapshotPayload(p->SESpkt.payload, state.snapshot);
    state.dirty = false;
    state.last_sent_ms = now_ms;
    local_credit_gen_ = state.snapshot.credit_gen;
    local_credit_last_sent_gen_ = state.snapshot.credit_gen;
    last_advertised_credit_ = state.snapshot.unexpected_msg_credits;
    last_credit_sent_ms_ = now_ms;
    local_credit_dirty_ = false;
    local_credit_dirty_since_ms_ = 0;
    pending_credit_job_id_ = 0;
    noteRudCreditCpSent();
    if (pending_credit_reason_ == CreditControlReason::REFRESH) {
        noteRudCreditRefreshSent();
    } else if (pending_credit_reason_ == CreditControlReason::RESYNC_RESPONSE) {
        noteRudCreditResyncRspSent();
    }
    pending_credit_reason_ = CreditControlReason::NONE;
    noteRudStandaloneFallbackSent();
    return true;
}

bool PDC::sendCtrlCreditReq(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return false;
    }

    if (pending_credit_req_job_id_ == 0) {
        return false;
    }

    const int64_t now_ms = nowMs();
    if (!tryConsumeCtrlBudget(CREDIT_REQ, now_ms)) {
        ctrl_tx_deferred_ = true;
        return false;
    }

    auto &peer = peerCreditStateForJob(pending_credit_req_job_id_);
    p->PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    p->PDS_header.RUOD_cp_header.ctl_type = Credit_req;
    p->PDS_header.RUOD_cp_header.flags.ar = 0;
    p->PDS_header.RUOD_cp_header.flags.syn = 0;
    p->PDS_header.RUOD_cp_header.psn = 0;
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.pdc_info = 0;
    p->PDS_header.RUOD_cp_header.payload = 0;
    encodeCreditReqPayload(p->SESpkt.payload, pending_credit_req_job_id_, peer.credit_gen_seen);
    peer.last_credit_req_ms = now_ms;
    noteRudCreditReqSent();
    noteRudCreditResyncReqSent();
    noteRudStandaloneFallbackSent();
    pending_credit_req_job_id_ = 0;
    return true;
}

bool PDC::sendCtrlSack(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return false;
    }

    uint32_t base_psn = 0;
    const uint32_t bitmap = buildRudSackBitmap(&base_psn);
    const int64_t now_ms = nowMs();
    if (!shouldSendSack(base_psn, bitmap, now_ms)) {
        noteRudCtrlSackSuppressed();
        rud_sack_pending = false;
        rud_sack_first_ms = 0;
        LOG_DEBUG(__FUNCTION__,
                  formatLogMessage("Suppress duplicate SACK base_psn=" + std::to_string(base_psn) +
                                   " bitmap=0x" + std::to_string(bitmap)));
        return false;
    }
    if (!tryConsumeCtrlBudget(SACK_CTRL, now_ms)) {
        noteRudCtrlSackSuppressed();
        ctrl_tx_deferred_ = true;
        return false;
    }
    p->PDS_header.RUOD_cp_header.ctl_type = SACK;
    p->PDS_header.RUOD_cp_header.psn = 0;
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.flags.isrod = 0;
    p->PDS_header.RUOD_cp_header.flags.ar = 0;
    p->PDS_header.RUOD_cp_header.payload = base_psn;
    storeSackBitmap(p->SESpkt.payload, bitmap);
    noteSackSent(base_psn, bitmap, now_ms);
    rud_sack_pending = false;
    rud_sack_first_ms = 0;
    noteRudStandaloneFallbackSent();
    return true;
}

/**
 * @brief Send Negotiation control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::sendCtrlNegotiation(PDStoNET_pkt *p)
{
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Negotiation control packet"));
    
    if(!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }
    
    p->PDS_header.RUOD_cp_header.flags.isrod = (mode == ROD) ? 1 : 0;
    p->PDS_header.RUOD_cp_header.ctl_type = gen_cm; 
    p->PDS_header.RUOD_cp_header.flags.ar = 1;
    p->PDS_header.RUOD_cp_header.flags.syn = 0;
    p->PDS_header.RUOD_cp_header.psn = tx_cur_psn;
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.pdc_info = 0;
    p->PDS_header.RUOD_cp_header.payload = 0x0; 

    std::stringstream negotiation_info;
    negotiation_info << "Negotiation control packet parameters - gen_cm: " << CM_TYPE_STR(gen_cm)
                        << ", PSN: " << tx_cur_psn
                        << ", SPDCID: " << SPDCID
                        << ", DPDCID: " << DPDCID;
    LOG_DEBUG(__FUNCTION__, formatLogMessage(negotiation_info.str()));
    
    LOG_INFO(__FUNCTION__, formatLogMessage("Negotiation control packet construction complete"));
}

/**
 * @brief Get unacknowledged packet count // 获取未确认包计数
 * @return Number of unacknowledged packets // 未确认包数量
 */
int PDC::getUnackCount() const
{
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Get unacknowledged packet count: " + std::to_string(unack_cnt)));
    return unack_cnt;
}

/**
 * @brief Get all acknowledgment status (I_PDC judges through unack_cnt) 
 * @return Whether all are acknowledged // 是否全部已确认
 */
bool PDC::getAllACKStatus() const {
    bool all_ack = (unack_cnt == 0);
    LOG_DEBUG(__FUNCTION__, formatLogMessage("获取全部确认状态 - unack_cnt: " + std::to_string(unack_cnt) + ", allACK: " + std::string(all_ack ? "true" : "false")));
    return all_ack;
}

/**
 * @brief Get open message count // 获取打开消息计数
 * @return Number of open messages // 打开消息数量
 */
int PDC::getOpenMsgCount() const
{
    LOG_DEBUG(__FUNCTION__, formatLogMessage("获取打开消息计数: " + std::to_string(open_msg)));
    return open_msg;
}

/**
 * @brief 获取PDC是否可以安全关闭的状态
 * @param unack_cnt_out 输出未确认包计数
 * @param allACK_out 输出全部确认状态
 * @param open_msg_out 输出打开消息计数
 */
void PDC::getCloseStatus(int& unack_cnt_out, bool& allACK_out, int& open_msg_out) const
{
    LOG_INFO(__FUNCTION__, formatLogMessage("获取关闭状态信息"));
    
    unack_cnt_out = unack_cnt;
    allACK_out = allACK;
    open_msg_out = open_msg;
    
    std::stringstream status_info;
    status_info << "关闭状态 - unack_cnt: " << unack_cnt
                << ", allACK: " << (allACK ? "true" : "false")
                << ", open_msg: " << open_msg;
    LOG_DEBUG(__FUNCTION__, formatLogMessage(status_info.str()));
}

/**
 * @brief 处理接收到的NACK包
 * @param pkt NACK包
 */
void PDC::rxNack(PDStoNET_pkt *pkt){
    //FUNCTION_LOG_ENTRY();

    if(!pkt) {
        LOG_ERROR(__FUNCTION__, "输入数据包指针为空");
        //FUNCTION_LOG_EXIT();
        return;
    }

    uint32_t psn = pkt->PDS_header.nack_header.nack_psn;

    
    std::stringstream nack_info;
    nack_info << "接收NACK - PSN: " << psn
                << ", nack_code: " << pkt->PDS_header.nack_header.nack_code;
    LOG_WARN(__FUNCTION__, nack_info.str());
    std::cout << getCurrentTimestamp() << "PDC接收NACK - PSN: " << psn << std::endl;

    if(isClose(pkt->PDS_header.nack_header.nack_code)){
        LOG_INFO(__FUNCTION__, "收到关闭NACK，设置关闭错误标志");
        std::cout << getCurrentTimestamp() << "PDC收到关闭NACK，触发关闭错误" << std::endl;
        close_error = true;
    }else{
        if (rud_tx_sacked_psns.count(psn) != 0) {
            return;
        }
        if(tx_pkt_map.find(psn) == tx_pkt_map.end()) {
            LOG_ERROR(__FUNCTION__, "未找到对应PSN的发送包元数据");
            //FUNCTION_LOG_EXIT();
            return;
        }

        TX_pkt_meta meta = tx_pkt_map.at(psn);

        if(meta.retry_cnt < Max_RTO_Retx_Cnt){
            meta.retry_cnt ++;
            meta.rto = Base_RTO * (1 << meta.retry_cnt) ;
        
            std::stringstream retry_info;
            retry_info << "Retransmit packet - PSN: " << psn
                        << ", retry_cnt: " << meta.retry_cnt
                        << ", new_rto: " << meta.rto;
            LOG_INFO(__FUNCTION__, retry_info.str());
            std::cout << getCurrentTimestamp() << "I_PDCRetransmit packet - PSN: " << psn
                        << ", retry_cnt: " << meta.retry_cnt << std::endl;
        
            reTx(psn);
        }else{
            LOG_ERROR(__FUNCTION__, "重传次数超限，设置关闭错误标志");
            std::cout << getCurrentTimestamp() << "I_PDC重传次数超限，触发关闭错误" << std::endl;
            close_error = true;
        }
    }
    //FUNCTION_LOG_EXIT();
}

/**
 * @brief 发送请求包
 * @param next_hdr 下一个头部类型
 * @param retx 重传标志
 * @param ar ACK请求标志
 * @param psn 包序列号
 * @param syn SYN标志
 * @param pkt 包数据
 */
void PDC::sendReq(PDS_next_hdr next_hdr,uint8_t retx,uint8_t ar,uint32_t psn,uint8_t syn,const SEStoPDS_pkt *pkt){
    // Perform packet header encapsulation here // 这里进行包头封装
    PDStoNET_pkt p = {};
    p.dst_fep = dst_fep;
    p.src_fep = src_fep;
    p.PDS_type = RUOD_req_header;
    p.PDS_header.RUOD_req_header.type = isRudMode() ? RUD_REQ : ROD_REQ;
    p.PDS_header.RUOD_req_header.next_hdr = next_hdr;
    p.PDS_header.RUOD_req_header.flags.syn = syn;
    p.PDS_header.RUOD_req_header.flags.retx = retx;
    p.PDS_header.RUOD_req_header.flags.ar = ar;
    p.PDS_header.RUOD_req_header.clear_psn_off =psn - clear_psn ;
    p.PDS_header.RUOD_req_header.psn = psn;
    p.PDS_header.RUOD_req_header.spdcid = SPDCID;
    if(syn == 0)p.PDS_header.RUOD_req_header.dpdcid = DPDCID;
    else {
        
        p.PDS_header.RUOD_req_header.pdc_info = 0;      
        p.PDS_header.RUOD_req_header.psn_off = psn - start_psn;
    }
    p.SESpkt = *pkt;
    tx_pkt_buffer.insert(std::make_pair(psn,p)); 

    TX_pkt_meta meta;
    meta.rto = Base_RTO;
    meta.tx_pkt_handle = 0;
    meta.retry_cnt = 0;
    if (pkt &&
        pkt->bth_type == Standard_Header &&
        mode == RUD) {
        meta.job_id = pkt->bth_header.Standard_Header.job_id;
        meta.msg_id = pkt->bth_header.Standard_Header.msg_id;
        meta.dst_fep = dst_fep;
        meta.is_request_som = pkt->bth_header.Standard_Header.som;
        if (pkt->bth_header.Standard_Header.opcode == 1 &&
            pkt->bth_header.Standard_Header.som) {
            meta.is_send_som = true;
        }
        if (meta.job_id != 0) {
            std::lock_guard<std::mutex> lock(g_request_tx_registry_mu);
            bool found = false;
            for (auto &entry : g_request_tx_registry) {
                if (entry.owner == this &&
                    entry.job_id == meta.job_id &&
                    entry.msg_id == meta.msg_id &&
                    entry.dst_fep == meta.dst_fep) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                g_request_tx_registry.push_back(RequestTxRegistryEntry{this, meta.job_id, meta.msg_id, meta.dst_fep});
            }
        }
    }
    tx_pkt_map.insert(std::make_pair(psn, meta));

    if(USE_RTO){
        startPacketTimer(psn, 0); 
    }

    if (public_net_queue) {
        public_net_queue->push(p);
        LOG_INFO(__FUNCTION__, formatLogMessage("将请求包压入公共网络队列"));
    } else {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        tx_pkt_q.push(p);
        LOG_INFO(__FUNCTION__, formatLogMessage("将请求包压入本地网络队列"));
    }
}
/**
 * @brief 发送ACK包
 * @param next_hdr 下一个头部类型
 * @param retx 重传标志
 * @param req 请求标志
 * @param psn 包序列号
 * @param pkt 包数据
 * @param gtd_del 保证传递标志
 */
void PDC::sendAck(PDS_next_hdr next_hdr,
                  uint8_t retx,
                  uint8_t req,
                  uint32_t psn,
                  SEStoPDS_pkt *pkt,
                  bool gtd_del,
                  uint32_t credit_job_id){
    //FUNCTION_LOG_ENTRY();

    
    std::stringstream params;
    params << "发送ACK参数 - next_hdr: " << next_hdr
            << ", retx: " << (int)retx
            << ", req: " << (int)req
            << ", psn: " << psn
            << ", gtd_del: " << (gtd_del ? "true" : "false")
            << ", pkt: " << (pkt ? "非空" : "空");
    LOG_INFO(__FUNCTION__, params.str());

    
    std::stringstream state_info;
    state_info << "PDC状态 - SPDCID: " << SPDCID
                << ", DPDCID: " << DPDCID
                << ", cack_psn: " << cack_psn;
    LOG_DEBUG(__FUNCTION__, state_info.str());

    PDStoNET_pkt p = {};
    p.dst_fep = dst_fep;
    p.src_fep = src_fep;
    p.PDS_type = RUOD_ack_header;
    p.PDS_header.RUOD_ack_header.type = PDS_type::ACK;
    p.PDS_header.RUOD_ack_header.next_hdr = next_hdr;
    p.PDS_header.RUOD_ack_header.flags.retx = retx;
    p.PDS_header.RUOD_ack_header.flags.req = req;
    p.PDS_header.RUOD_ack_header.flags.x = 0;
    // ACK wire format: ack_psn = cack_psn + ack_psn_off.
    // Keep it simple/robust for the prototype: report "ACK for psn" using an in-order base.
    // This avoids triggering spurious ACK_REQ loops when the local cack_psn is used for unrelated bookkeeping.
    const uint32_t cack_base = (psn > 0) ? (psn - 1) : 0;
    p.PDS_header.RUOD_ack_header.cack_psn = cack_base;
    p.PDS_header.RUOD_ack_header.ack_psn_off = psn - cack_base;
    p.PDS_header.RUOD_ack_header.spdcid = SPDCID;
    p.PDS_header.RUOD_ack_header.dpdcid = DPDCID;
    maybeFillAckControlExt(&p, nowMs(), credit_job_id);

    if (pkt != nullptr)
    {
        p.SESpkt = *pkt;
        LOG_DEBUG(__FUNCTION__, formatLogMessage("包含SES层数据"));
    }

    
    std::stringstream ack_info;
    ack_info << "构造ACK包 - PSN: " << psn
            << ", CACK_PSN: " << cack_psn
            << ", ACK_PSN_OFF: " << (psn - cack_psn);
    LOG_INFO(__FUNCTION__, formatLogMessage(ack_info.str()));

    if (public_net_queue) {
        public_net_queue->push(p);
    } else {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        tx_pkt_q.push(p);
    }
    LOG_DEBUG(__FUNCTION__, formatLogMessage("ACK包已加入发送队列"));

    if (gtd_del)
    { 
        LOG_INFO(__FUNCTION__, formatLogMessage("保证交付模式,保存到ACK缓冲区"));
        TX_pkt_meta meta;
        meta.tx_pkt_handle = 0;
        meta.retry_cnt = 0;
        meta.rto = Base_RTO;
        tx_pkt_map[psn] = meta;
        tx_ack_buffer[psn] = p;
        if (USE_RTO && psn != 0) {
            startPacketTimer(psn, 0);
        }
    }

    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] tx_ack包发送,psn : " << psn << "cack_psn :" << cack_psn << std::endl;

    //FUNCTION_LOG_EXIT();
}
/**
 * @brief 发送NACK包
 * @param retx 重传标志
 * @param nack_psn NACK的PSN
 * @param nack_code NACK错误码
 * @param payload 载荷数据
 * @param pkt 包数据
 */
void PDC::sendNack(uint8_t retx, uint32_t nack_psn, PDS_Nack_Codes nack_code, uint32_t payload,SEStoPDS_pkt *pkt){
    //FUNCTION_LOG_ENTRY();

    const int64_t now_ms = nowMs();
    const NackCtrlClass nack_class = classifyNack(nack_code);
    if (nack_class == NackCtrlClass::RESOURCE_RECOVERABLE) {
        if (!shouldSendRecoverableNack(nack_code, nack_psn, payload, now_ms)) {
            noteRudCtrlNackSuppressed();
            noteRudCtrlNackSuppressedByClass(static_cast<uint8_t>(nack_class));
            return;
        }
        if (!tryConsumeBudgetClassB(now_ms)) {
            noteRudCtrlNackSuppressed();
            noteRudCtrlNackSuppressedByClass(static_cast<uint8_t>(nack_class));
            return;
        }
        last_resource_nack_code_ = nack_code;
        last_resource_nack_psn_ = nack_psn;
        last_resource_nack_payload_ = payload;
        last_resource_nack_ms_ = now_ms;
    }

    
    std::stringstream nack_params;
    nack_params << "发送NACK参数 - retx: " << (int)retx
                << ", nack_psn: " << nack_psn
                << ", nack_code: " << NACK_CODE_STR(nack_code)
                << ", payload: " << payload;
    LOG_WARN(__FUNCTION__, nack_params.str());

    std::cout << getCurrentTimestamp() << "I_PDC发送NACK包 - PSN: " << nack_psn
                << ", code: " << NACK_CODE_STR(nack_code) << std::endl;

    // Currently parameters are set this way, need to add more // 目前参数先定成这样，需要再加
    PDStoNET_pkt p = {};
    p.dst_fep = dst_fep;
    p.src_fep = src_fep;
    p.PDS_type = nack_header;
    p.PDS_header.nack_header.type = NACK;
    p.PDS_header.nack_header.next_hdr = UET_HDR_NONE;//todo 根据需要设置
    p.PDS_header.nack_header.flags.m = 0x0;
    p.PDS_header.nack_header.flags.retx = retx;
    p.PDS_header.nack_header.flags.nt = 0x0;    
    p.PDS_header.nack_header.nack_psn = nack_psn;
    p.PDS_header.nack_header.nack_code = nack_code;

    
    if(nack_code == UET_NO_PDC_AVAIL || nack_code == UET_NO_CCC_AVAIL || nack_code == UET_NO_BITMAP || nack_code == UET_INV_DPDCID || nack_code == UET_PDC_HDR_MISMATCH || nack_code == UET_NO_RESOURCE){
        p.PDS_header.nack_header.spdcid = 0x0;
        LOG_DEBUG(__FUNCTION__, "特殊NACK码，设置SPDCID为0");
    }
    else {
        p.PDS_header.nack_header.spdcid = SPDCID;
    }
    p.PDS_header.nack_header.dpdcid = DPDCID;
    p.PDS_header.nack_header.payload = payload;

    if(pkt) {
        p.SESpkt = *pkt;
        LOG_DEBUG(__FUNCTION__, "NACK包包含SES层数据");
    }
    else {
        p.SESpkt = {};
        LOG_DEBUG(__FUNCTION__, "NACK包不包含SES层数据");
    }

    if (public_net_queue) {
        public_net_queue->push(p);
    } else {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        tx_pkt_q.push(p);
    }
    noteRudCtrlNackSent();
    noteRudCtrlNackSentByClass(static_cast<uint8_t>(nack_class));
    LOG_INFO(__FUNCTION__, "NACK包已加入发送队列");

    std::cout << getCurrentTimestamp() << "I_PDC NACK包已发送 - PSN: " << p.PDS_header.nack_header.nack_psn
                << ", code: " << NACK_CODE_STR(nack_code) << std::endl;

    //FUNCTION_LOG_EXIT();
}
/**
 * @brief 发送请求给网络层
 * @param req 请求包
 */
void PDC::txReq(PDS_PDC_req *req){

    if(!req) {
        LOG_ERROR(__FUNCTION__, "输入请求指针为空");
        //FUNCTION_LOG_EXIT();
        return;
    }
    markActivity();

    uint32_t psn = setPsn();

    
    std::stringstream req_info;
    req_info << "发送请求包 - tx_pkt_handle: " << req->tx_pkt_handle
                << ", next_hdr: " << req->next_hdr
                << ", som: " << (req->som ? "true" : "false")
                << ", eom: " << (req->eom ? "true" : "false")
                << ", psn: " << psn
                << ", SYN: " << (SYN ? "true" : "false");
    LOG_INFO(__FUNCTION__, req_info.str());

    std::cout << getCurrentTimestamp() << "I_PDC发送请求包 - PSN: " << psn
                << ", handle: " << req->tx_pkt_handle << std::endl;

    updateTxPsnTracker();

    TX_pkt_meta meta;
    meta.retry_cnt = 0;                         
    meta.tx_pkt_handle = req->tx_pkt_handle;
    meta.rto = Base_RTO;
    meta.is_retry = req->is_retry;
    if (req->pkt.bth_type == Standard_Header &&
        mode == RUD) {
        meta.job_id = req->pkt.bth_header.Standard_Header.job_id;
        meta.msg_id = req->pkt.bth_header.Standard_Header.msg_id;
        meta.dst_fep = dst_fep;
        meta.is_request_som = req->som;
        if (req->pkt.bth_header.Standard_Header.opcode == 1 && req->som) {
            meta.is_send_som = true;
        }
        if (meta.job_id != 0) {
            std::lock_guard<std::mutex> lock(g_request_tx_registry_mu);
            bool found = false;
            for (auto &entry : g_request_tx_registry) {
                if (entry.owner == this &&
                    entry.job_id == meta.job_id &&
                    entry.msg_id == meta.msg_id &&
                    entry.dst_fep == meta.dst_fep) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                g_request_tx_registry.push_back(RequestTxRegistryEntry{this, meta.job_id, meta.msg_id, meta.dst_fep});
            }
        }
    }
    tx_pkt_map.insert(std::make_pair(psn, meta));
    
    LOG_DEBUG(__FUNCTION__, "包元数据已保存");

    
    if(req->som) {
        open_msg += 1;
        LOG_DEBUG(__FUNCTION__, "消息开始标记，open_msg增加");
        std::cout << getCurrentTimestamp() << "I_PDC消息开始，open_msg: " << open_msg << std::endl;
    }
    if(req->eom) {
        open_msg -= 1;
        LOG_DEBUG(__FUNCTION__, "消息结束标记，open_msg减少");
        std::cout << getCurrentTimestamp() << "I_PDC消息结束，open_msg: " << open_msg << std::endl;
    }

    std::stringstream msg_info;
    msg_info << "当前open_msg计数: " << open_msg;
    LOG_DEBUG(__FUNCTION__, msg_info.str());

    if(req->eom == 1 || Enb_ACK_Per_Pkt) sendReq(req->next_hdr,0,1,psn,SYN,&req->pkt);
    else sendReq(req->next_hdr,0,0,psn,SYN,&req->pkt);
    
    LOG_INFO(__FUNCTION__, "请求包已发送");
}

/**
 * @brief 发送响应给网络层
 * @param rsp 响应包
 */
void PDC::txRsp(SES_PDC_rsp *rsp){
    //FUNCTION_LOG_ENTRY();
    markActivity();

    
    std::stringstream debug_info;
    debug_info << "tx_rsp调用 - 查找句柄: " << rsp->rx_pkt_handle
                << ", rx_pkt_map大小: " << rx_pkt_map.size();
    LOG_INFO(__FUNCTION__, debug_info.str());

    
    if (!rx_pkt_map.empty()) {
        std::stringstream map_keys;
        map_keys << "rx_pkt_map中的所有句柄: ";
        for (const auto& pair : rx_pkt_map) {
            map_keys << pair.first << " ";
        }
        LOG_DEBUG(__FUNCTION__, map_keys.str());
    }

    
    if (rx_pkt_map.find(rsp->rx_pkt_handle) == rx_pkt_map.end()) {
        std::stringstream error_info;
        error_info << "错误：未找到句柄 " << rsp->rx_pkt_handle << " 在rx_pkt_map中";
        LOG_ERROR(__FUNCTION__, error_info.str());
        //FUNCTION_LOG_EXIT();
        return;
    }

    RX_pkt_meta meta = rx_pkt_map.at(rsp->rx_pkt_handle);

    std::stringstream meta_info;
    meta_info << "找到元数据 - PSN: " << meta.psn
                << ", SPDCID: " << meta.spdcid;
    LOG_INFO(__FUNCTION__, meta_info.str());

    updateRxPsnTracker(&meta,rsp->gtd_del);
    // SES response may carry data payload (e.g., READ response).
    PDS_next_hdr next_hdr = PDS_next_hdr::UET_HDR_RESPONSE;
    bool is_last = true;
    if (rsp->pkt.bth_type == Semantic_Response_with_Data_Header) {
        next_hdr = PDS_next_hdr::UET_HDR_RESPONSE_DATA;
        const auto& hdr = rsp->pkt.bth_header.Semantic_Response_with_Data_Header;
        const uint64_t end_off = static_cast<uint64_t>(hdr.message_offset) +
                                 static_cast<uint64_t>(hdr.payload_length);
        is_last = (end_off >= hdr.modified_length);
    } else if (rsp->rep_len == 0) {
        next_hdr = PDS_next_hdr::UET_HDR_NONE;
    }

    sendAck(next_hdr,0,0,meta.psn,&rsp->pkt,rsp->gtd_del);
    if (is_last) {
        rx_pkt_map.erase(rsp->rx_pkt_handle);//Delete metadata //删除元数据
        decPending();
    }

    //FUNCTION_LOG_EXIT();
}
/**
 * @brief 设置公共队列
 * @param net_q 网络队列
 * @param ses_req_q SES请求队列
 * @param ses_rsp_q SES响应队列
 * @param close_q 关闭队列
 */
void PDC::setPublicQueues(ThreadSafeQueue<PDStoNET_pkt>* net_q,
                    ThreadSafeQueue<PDC_SES_req>* ses_req_q,
                    ThreadSafeQueue<PDC_SES_rsp>* ses_rsp_q,
                    ThreadSafeQueue<uint16_t>* close_q)
{
    public_net_queue = net_q;
    public_ses_req_queue = ses_req_q;
    public_ses_rsp_queue = ses_rsp_q;
    public_close_queue = close_q;
}

int64_t PDC::nowMs() const
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void PDC::markActivity()
{
    last_activity_ms.store(nowMs(), std::memory_order_relaxed);
}

void PDC::incPending()
{
    pending_ops.fetch_add(1, std::memory_order_relaxed);
    markActivity();
}

void PDC::decPending()
{
    int before = pending_ops.load(std::memory_order_relaxed);
    if (before > 0) {
        pending_ops.fetch_sub(1, std::memory_order_relaxed);
    }
    markActivity();
}

/**
 * @brief 判断PDC是否可以安全关闭
 * @return 是否可以关闭
 */
bool PDC::canSafelyClose(){
    const int pending = pending_ops.load(std::memory_order_relaxed);
    const int64_t last_ms = last_activity_ms.load(std::memory_order_relaxed);
    const int64_t now_ms = nowMs();
    const bool idle_ok = (last_ms > 0) && ((now_ms - last_ms) >= kIdleCloseMs);
    size_t tx_pending_count = 0;
    for (const auto &entry : tx_pkt_map) {
        const uint32_t psn = entry.first;
        const TX_pkt_meta &meta = entry.second;
        bool count_as_inflight = false;
        if (meta.job_id != 0) {
            const SenderTerminalKey request_key{meta.job_id, meta.msg_id, meta.dst_fep};
            if (request_terminalized_keys_.count(request_key) == 0) {
                count_as_inflight = true;
            }
            if (meta.is_read_response_data) {
                const ReadResponseTerminalKey read_key{meta.job_id, meta.msg_id, meta.dst_fep};
                if (read_response_terminalized_keys_.count(read_key) != 0) {
                    count_as_inflight = false;
                }
            }
        } else {
            auto ack_it = tx_ack_buffer.find(psn);
            if (ack_it != tx_ack_buffer.end() && !isLowValueStandaloneControlPacket(ack_it->second)) {
                count_as_inflight = true;
            }
            auto pkt_it = tx_pkt_buffer.find(psn);
            if (pkt_it != tx_pkt_buffer.end() && !isLowValueStandaloneControlPacket(pkt_it->second)) {
                count_as_inflight = true;
            }
        }
        if (count_as_inflight) {
            ++tx_pending_count;
        }
    }
    const bool tx_inflight = tx_pending_count != 0;
    bool rx_packet_inflight = false;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        rx_packet_inflight = !rx_pkt_q.empty();
    }
    const size_t rx_message_count = rud_rx_messages_.size();
    const bool rx_inflight = (rx_message_count != 0) || rx_packet_inflight;
    const bool no_unacked_data = (unack_cnt == 0);
    bool canClose = allACK && no_unacked_data && !tx_inflight && (open_msg == 0) &&
                    (pending == 0) && !rx_inflight && idle_ok;
    
    std::stringstream status_info;
    status_info << "PDC关闭状态检查 - SPDCID: " << SPDCID
                << ", unack_cnt: " << unack_cnt
                << ", allACK: " << (allACK ? "true" : "false")
                << ", no_unacked_data: " << (no_unacked_data ? "true" : "false")
                << ", tx_pending_count: " << tx_pending_count
                << ", tx_inflight: " << (tx_inflight ? "true" : "false")
                << ", open_msg: " << open_msg
                << ", pending_ops: " << pending
                << ", rud_rx_messages: " << rx_message_count
                << ", rx_pkt_q_nonempty: " << (rx_packet_inflight ? "true" : "false")
                << ", rx_inflight: " << (rx_inflight ? "true" : "false")
                << ", idle_ms: " << (last_ms > 0 ? (now_ms - last_ms) : -1)
                << ", idle_ok: " << (idle_ok ? "true" : "false")
                << ", 可以关闭: " << (canClose ? "是" : "否");
    LOG_INFO(__FUNCTION__, formatLogMessage(status_info.str()));
    
    return canClose;
}

/**
 * @brief 启动包的计时器
 * @param psn 包序列号
 * @param retry_count 当前重试次数
 */
void PDC::startPacketTimer(uint32_t psn, uint16_t retry_count)
{
    if (!rto_timer_.startTimer(psn, Base_RTO, retry_count)) {
        LOG_ERROR("PDC::startPacketTimer", 
                 formatLogMessage("启动计时器失败 - PSN: " + std::to_string(psn)));
    }
}

/**
 * @brief 停止包的计时器
 * @param psn 包序列号
 */
void PDC::stopPacketTimer(uint32_t psn)
{
    if (!rto_timer_.stopTimer(psn)) {
        LOG_DEBUG("PDC::stopPacketTimer", 
                 formatLogMessage("停止计时器失败或不存在 - PSN: " + std::to_string(psn)));
    }
}

/**
 * @brief 更新包的RTO时间
 * @param psn 包序列号
 * @param new_rto 新的RTO时间
 */
void PDC::updatePacketRTO(uint32_t psn, uint16_t new_rto)
{
    if (!rto_timer_.updateRTO(psn, new_rto)) {
        LOG_WARN("PDC::updatePacketRTO", 
                 formatLogMessage("更新RTO失败 - PSN: " + std::to_string(psn)));
    }
}

/**
 * @brief 清理所有包的计时器
 */
void PDC::clearAllPacketTimers()
{
    rto_timer_.clearAllTimers();
    LOG_INFO("PDC::clearAllPacketTimers", 
             formatLogMessage("清理所有包计时器"));
}

/**
 * @brief 获取计时器状态信息
 * @param psn 包序列号
 * @return 计时器状态信息
 */
RTOTimer::TimerItem PDC::getTimerInfo(uint32_t psn) const
{
    return rto_timer_.getTimerInfo(psn);
}

/**
 * @brief 检查计时器是否活跃
 * @param psn 包序列号
 * @return 是否活跃
 */
bool PDC::isTimerActive(uint32_t psn) const
{
    return rto_timer_.isTimerActive(psn);
}

/**
 * @brief 获取活跃计时器数量
 * @return 活跃计时器数量
 */
size_t PDC::getActiveTimerCount() const
{
    return rto_timer_.getActiveTimerCount();
}

/**
 * @brief 检查清理状态
 */

void PDC::chkClear()
{ 
    if (tx_ack_buffer.size() + 5 >= tx_ack_buffer_capa)
        requestControl(CLR_REQ);
}

/**
 * @brief 检查裁剪状态
 * @return 裁剪状态检查结果
 */
bool PDC::chkTrim()
{
    return false;
    
}

/**
 * @brief 设置FEP地址
 * @param dst 目标IP地址
 * @param src 源IP地址
 */
void PDC::setFep(uint32_t dst, uint32_t src)
{
    dst_fep = dst;
    src_fep = src;
}
