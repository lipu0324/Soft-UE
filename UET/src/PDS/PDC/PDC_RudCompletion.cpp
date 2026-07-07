#include "PDC_RudInternals.hpp"

void PDC::pruneCompletedSendTombstones(int64_t now_ms)
{
    for (auto it = rud_completed_send_tombstones_.begin();
         it != rud_completed_send_tombstones_.end();) {
        const SendCompletionTombstone &tombstone = it->second;
        if (tombstone.completed_at_ms <= 0 ||
            now_ms < tombstone.completed_at_ms ||
            (now_ms - tombstone.completed_at_ms) > kUnexpectedAcceptedTimeoutMs) {
            it = rud_completed_send_tombstones_.erase(it);
        } else {
            ++it;
        }
    }
}

void PDC::rememberCompletedSendTombstone(const RxMessageKey &key,
                                         uint32_t modified_length,
                                         int64_t completed_at_ms)
{
    pruneCompletedSendTombstones(completed_at_ms);
    SendCompletionTombstone &tombstone = rud_completed_send_tombstones_[key];
    tombstone.modified_length = modified_length;
    tombstone.completed_at_ms = completed_at_ms;
}

bool PDC::replayCompletedSendDuplicate(const RxMessageKey &key, uint16_t rx_pkt_handle)
{
    const int64_t now = nowMs();
    pruneCompletedSendTombstones(now);

    const auto it = rud_completed_send_tombstones_.find(key);
    if (it == rud_completed_send_tombstones_.end()) {
        return false;
    }

    PDC_RX_completion completion{};
    completion.type = PDC_RX_completion_type::SEND;
    completion.notify_kind = PDC_RX_completion_notify_kind::DUPLICATE_REPLAY;
    completion.opcode = static_cast<uint8_t>(key.opcode);
    completion.job_id = key.job_id;
    completion.msg_id = key.msg_id;
    completion.src_fep = key.src_fep;
    completion.pdcid = key.pdcid;
    completion.rx_pkt_handle = rx_pkt_handle;
    completion.total_len = it->second.modified_length;
    completion.modified_length = it->second.modified_length;
    completion.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK);
    completion.success = true;
    completion.response_required = true;
    complete_rx_operation_(completion);
    return true;
}

void PDC::emitRxCompletion(const RxMessageKey &key,
                           const RxMessageContext &ctx,
                           PDC_RX_completion_type type,
                           uint8_t return_code,
                           bool success,
                           PDC_RX_completion_notify_kind notify_kind,
                           uint32_t modified_length,
                           PDC_RX_failure_kind failure_kind,
                           PDS_Nack_Codes pds_nack_code)
{
    PDC_RX_completion completion{};
    completion.type = type;
    completion.notify_kind = notify_kind;
    completion.opcode = static_cast<uint8_t>(key.opcode);
    completion.job_id = key.job_id;
    completion.msg_id = key.msg_id;
    completion.src_fep = key.src_fep;
    completion.pdcid = key.pdcid;
    completion.rx_pkt_handle = ctx.rx_pkt_handle;
    completion.completion_key = ctx.placement.completion_key;
    completion.total_len = ctx.total_len;
    completion.modified_length = modified_length;
    completion.return_code = return_code;
    completion.failure_kind = failure_kind;
    completion.pds_nack_code = pds_nack_code;
    completion.success = success;
    completion.response_required = ctx.placement.response_required;
    complete_rx_operation_(completion);
}

void PDC::releaseRxMessageContext(const RxMessageKey &key, RxMessageContext &ctx, RudReleaseReason reason)
{
    if (reason != RudReleaseReason::NORMAL) {
        eraseRxHandle(ctx.rx_pkt_handle);
    }
    if (ctx.send_mode == RudSendPlacementMode::UNEXPECTED_BUFFERED) {
        std::lock_guard<std::mutex> lock(g_unexpected_send_registry_mu);
        for (auto it = g_unexpected_send_registry.begin(); it != g_unexpected_send_registry.end();) {
            if (it->owner == this && it->key == key) {
                it = g_unexpected_send_registry.erase(it);
            } else {
                ++it;
            }
        }
    }
    size_t released_blocks = 0;
    for (auto &entry : ctx.blocks) {
        sharedRudResourcePool().releaseArrivalBlock(entry.second);
        ++released_blocks;
    }
    if (released_blocks != 0) {
        noteRudArrivalBlockReleased(released_blocks);
    }
    if (ctx.unexpected) {
        const int64_t now = nowMs();
        const uint64_t residence_ms =
            (ctx.unexpected->created_at_ms > 0 && now >= ctx.unexpected->created_at_ms)
                ? static_cast<uint64_t>(now - ctx.unexpected->created_at_ms)
                : 0;
        const bool stale_partial_unexpected =
            !ctx.unexpected->semantic_accepted &&
            ctx.unexpected->last_activity_ms > 0 &&
            (now - ctx.unexpected->last_activity_ms) >= kUnexpectedPartialTimeoutMs;
        const bool close_reset_terminal_partial =
            reason == RudReleaseReason::CLOSE_RESET &&
            !ctx.unexpected->semantic_accepted &&
            !ctx.unexpected->matched_to_recv &&
            ctx.unexpected->last_activity_ms > 0 &&
            (now - ctx.unexpected->last_activity_ms + static_cast<int64_t>(Base_RTO)) >=
                kUnexpectedPartialTimeoutMs;
        if (stale_partial_unexpected || close_reset_terminal_partial) {
            noteRudUnexpectedPartialTimeoutCleanup();
        }
        noteRudUnexpectedReleased(ctx.unexpected->semantic_accepted,
                                  reason == RudReleaseReason::CLOSE_RESET,
                                  residence_ms);
        sharedRudResourcePool().releaseUnexpectedBuffer(ctx.unexpected->buffer);
        ctx.unexpected.reset();
    }
    ctx.blocks.clear();
    ctx.hot_block_bases = {{0, 0, 0, 0}};
    ctx.hot_block_ptrs = {{nullptr, nullptr, nullptr, nullptr}};
    rud_rx_messages_.erase(key);
}

void PDC::completeRxMessage(const RxMessageKey &key,
                            RxMessageContext &ctx,
                            PDC_RX_completion_type type,
                            uint8_t return_code,
                            bool success,
                            PDC_RX_completion_notify_kind notify_kind,
                            uint32_t modified_length,
                            PDC_RX_failure_kind failure_kind,
                            PDS_Nack_Codes pds_nack_code)
{
    if (ctx.completed || ctx.failed) {
        return;
    }

    if (success) {
        ctx.completed = true;
    } else {
        ctx.failed = true;
    }

    const uint32_t effective_modified_length = (modified_length == 0 && success) ? ctx.total_len : modified_length;
    if (success &&
        type == PDC_RX_completion_type::SEND &&
        notify_kind != PDC_RX_completion_notify_kind::SEMANTIC_ACCEPT) {
        rememberCompletedSendTombstone(key, effective_modified_length, nowMs());
    }
    emitRxCompletion(key,
                     ctx,
                     type,
                     return_code,
                     success,
                     notify_kind,
                     effective_modified_length,
                     failure_kind,
                     pds_nack_code);
    if (type != PDC_RX_completion_type::READ_RESPONSE) {
        decPending();
    }
    releaseRxMessageContext(key, ctx, RudReleaseReason::NORMAL);
}

bool PDC::extractSenderTerminalFromReq(const PDS_PDC_req &req, SenderTerminalCompletion *completion) const
{
    if (!completion ||
        mode != RUD ||
        !req.som ||
        req.pkt.bth_type != Standard_Header ||
        req.pkt.bth_header.Standard_Header.opcode != 1) {
        return false;
    }
    completion->job_id = req.pkt.bth_header.Standard_Header.job_id;
    completion->msg_id = req.pkt.bth_header.Standard_Header.msg_id;
    completion->dst_fep = dst_fep;
    return true;
}

bool PDC::emitRequestTerminalCompletion(const RequestTerminalCompletion &completion)
{
    if (!complete_request_terminal_ || completion.job_id == 0) {
        return false;
    }
    request_terminalized_keys_.insert(SenderTerminalKey{completion.job_id, completion.msg_id, completion.dst_fep});
    complete_request_terminal_(completion);
    return true;
}

bool PDC::emitRequestTerminalCompletion(const TX_pkt_meta &meta, SenderTerminalReason reason)
{
    if (!meta.is_request_som || meta.job_id == 0) {
        return false;
    }

    RequestTerminalCompletion completion{};
    completion.job_id = meta.job_id;
    completion.msg_id = meta.msg_id;
    completion.dst_fep = meta.dst_fep;
    completion.reason = reason;
    completion.terminalized_at_ms = nowMs();
    completion.close_state_at_terminalize = static_cast<uint8_t>(state);
    completion.unack_cnt_at_terminalize = static_cast<uint32_t>(std::max(unack_cnt, 0));
    completion.all_ack_at_terminalize = allACK;
    switch (reason) {
        case SenderTerminalReason::RTO_EXHAUSTED:
            completion.close_cause = RequestCloseCause::RTO_EXHAUST_PATH;
            break;
        case SenderTerminalReason::TEARDOWN_ORPHAN:
            completion.close_cause = RequestCloseCause::SAFE_CLOSE_TEARDOWN;
            break;
        case SenderTerminalReason::CLOSE_RESET:
        default:
            if (close_error) {
                completion.close_cause = RequestCloseCause::CLOSE_ERROR_PATH;
            } else if (closing || state == ACK_WAIT || state == CLOSE_ACK_WAIT || state == CLOSED) {
                completion.close_cause = RequestCloseCause::SAFE_CLOSE_TEARDOWN;
            } else {
                completion.close_cause = RequestCloseCause::UNKNOWN;
            }
            break;
    }
    uint32_t key_pending_count = 0;
    for (const auto &entry : tx_pkt_map) {
        const TX_pkt_meta &pending = entry.second;
        if (pending.job_id == completion.job_id &&
            pending.msg_id == completion.msg_id &&
            pending.dst_fep == completion.dst_fep) {
            ++key_pending_count;
        }
    }
    completion.tx_pending_count_at_terminalize = key_pending_count;
    return emitRequestTerminalCompletion(completion);
}

size_t PDC::terminalizeOutstandingRequests(SenderTerminalReason reason)
{
    size_t terminalized = 0;
    for (const auto &entry : tx_pkt_map) {
        if (emitRequestTerminalCompletion(entry.second, reason)) {
            ++terminalized;
        }
    }

    std::queue<PDS_PDC_req> pending_copy;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_copy = tx_req_q;
    }
    while (!pending_copy.empty()) {
        const PDS_PDC_req &req = pending_copy.front();
        if (mode == RUD &&
            req.som &&
            req.pkt.bth_type == Standard_Header) {
            RequestTerminalCompletion completion{};
            completion.job_id = req.pkt.bth_header.Standard_Header.job_id;
            completion.msg_id = req.pkt.bth_header.Standard_Header.msg_id;
            completion.dst_fep = dst_fep;
            completion.reason = reason;
            if (emitRequestTerminalCompletion(completion)) {
                ++terminalized;
            }
        }
        pending_copy.pop();
    }
    return terminalized;
}

bool PDC::emitSenderTerminalCompletion(const SenderTerminalCompletion &completion)
{
    if (!complete_sender_terminal_ || completion.job_id == 0) {
        return false;
    }

    const SenderTerminalKey key{completion.job_id, completion.msg_id, completion.dst_fep};
    if (!sender_terminalized_keys_.insert(key).second) {
        return false;
    }

    complete_sender_terminal_(completion);
    return true;
}

bool PDC::emitSenderTerminalCompletion(const TX_pkt_meta &meta, SenderTerminalReason reason)
{
    if (!meta.is_send_som || meta.job_id == 0) {
        return false;
    }

    SenderTerminalCompletion completion{};
    completion.job_id = meta.job_id;
    completion.msg_id = meta.msg_id;
    completion.dst_fep = meta.dst_fep;
    completion.reason = reason;
    return emitSenderTerminalCompletion(completion);
}

size_t PDC::terminalizeOutstandingSenderRetries(SenderTerminalReason reason)
{
    size_t terminalized = 0;
    for (const auto &entry : tx_pkt_map) {
        if (emitSenderTerminalCompletion(entry.second, reason)) {
            ++terminalized;
        }
    }

    std::queue<PDS_PDC_req> pending_copy;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_copy = tx_req_q;
    }
    while (!pending_copy.empty()) {
        SenderTerminalCompletion completion{};
        if (extractSenderTerminalFromReq(pending_copy.front(), &completion)) {
            completion.reason = reason;
            if (emitSenderTerminalCompletion(completion)) {
                ++terminalized;
            }
        }
        pending_copy.pop();
    }
    return terminalized;
}

bool PDC::extractReadResponseTerminalFromRsp(const SES_PDC_rsp &rsp,
                                             ReadResponseTerminalCompletion *completion) const
{
    if (!completion || rsp.pkt.bth_type != Semantic_Response_with_Data_Header) {
        return false;
    }
    const auto &hdr = rsp.pkt.bth_header.Semantic_Response_with_Data_Header;
    completion->job_id = hdr.job_id;
    completion->msg_id = hdr.read_request_msg_id;
    completion->dst_fep = dst_fep;
    return completion->job_id != 0;
}

bool PDC::emitReadResponseTerminalCompletion(const ReadResponseTerminalCompletion &completion)
{
    if (!complete_read_response_terminal_ || completion.job_id == 0) {
        return false;
    }

    const ReadResponseTerminalKey key{completion.job_id, completion.msg_id, completion.dst_fep};
    if (!read_response_terminalized_keys_.insert(key).second) {
        return false;
    }

    complete_read_response_terminal_(completion);
    return true;
}

bool PDC::emitReadResponseTerminalCompletion(const TX_pkt_meta &meta, ReadResponseTerminalReason reason)
{
    if (!meta.is_read_response_data || meta.job_id == 0) {
        return false;
    }

    ReadResponseTerminalCompletion completion{};
    completion.job_id = meta.job_id;
    completion.msg_id = meta.msg_id;
    completion.dst_fep = meta.dst_fep;
    completion.reason = reason;
    return emitReadResponseTerminalCompletion(completion);
}

size_t PDC::terminalizeOutstandingReadResponses(ReadResponseTerminalReason reason)
{
    size_t terminalized = 0;
    for (const auto &entry : tx_pkt_map) {
        if (emitReadResponseTerminalCompletion(entry.second, reason)) {
            ++terminalized;
        }
    }

    std::queue<SES_PDC_rsp> pending_copy;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_copy = tx_rsp_q;
    }
    while (!pending_copy.empty()) {
        ReadResponseTerminalCompletion completion{};
        if (extractReadResponseTerminalFromRsp(pending_copy.front(), &completion)) {
            completion.reason = reason;
            if (emitReadResponseTerminalCompletion(completion)) {
                ++terminalized;
            }
        }
        pending_copy.pop();
    }
    return terminalized;
}

void PDC::resetRudState()
{
    for (auto it = rud_rx_messages_.begin(); it != rud_rx_messages_.end();) {
        auto current = it++;
        releaseRxMessageContext(current->first, current->second, RudReleaseReason::CLOSE_RESET);
    }
    rud_completed_send_tombstones_.clear();
    rud_rx_ooo_psns.clear();
    rud_tx_sacked_psns.clear();
    rud_sack_pending = false;
    rud_gap_pending = false;
    rud_gap_psn = 0;
    rud_sack_first_ms = 0;
    rud_gap_first_ms = 0;
    rud_gap_last_nack_ms_ = 0;
    rud_gap_retry_interval_ms_ = kRudGapDelayMs;
    rud_gap_suppressed_in_window_ = false;
    rud_rsp_gap_psn_ = 0;
    rud_rsp_gap_first_ms_ = 0;
    rud_rsp_gap_last_nack_ms_ = 0;
    rud_rsp_gap_retry_interval_ms_ = kRudGapDelayMs;
    rud_rsp_gap_suppressed_in_window_ = false;
    rud_ctrl_budget_tokens_ = kRudCtrlBudgetCapacity;
    rud_ctrl_budget_last_refill_ms_ = 0;
    ctrl_tx_deferred_ = false;
    skip_ctrl_emit_once_ = false;
    last_ack_req_psn_ = 0;
    last_ack_req_ms_ = 0;
    last_sack_base_psn_ = 0;
    last_sack_bitmap_ = 0;
    last_sack_ms_ = 0;
    local_receiver_credits_.clear();
    peer_receiver_credits_.clear();
    observed_receiver_jobs_.clear();
    pending_credit_job_id_ = 0;
    pending_credit_req_job_id_ = 0;
    last_credit_ack_job_id_ = 0;
    local_credit_gen_ = 0;
    local_credit_last_sent_gen_ = 0;
    peer_credit_gen_seen_ = 0;
    peer_credit_available_ = 0;
    peer_credit_valid_ = false;
    local_credit_dirty_ = true;
    bootstrap_credit_used_ = false;
    last_advertised_credit_ = 0;
    last_unexpected_msgs_in_use_ = 0;
    last_pressure_sent_unexpected_msgs_in_use_ = 0;
    last_receiver_pressure_unexpected_byte_credits_ = 0;
    last_receiver_pressure_bitmap_blocks_available_ = 0;
    last_receiver_pressure_arrival_blocks_available_ = 0;
    local_credit_dirty_since_ms_ = 0;
    last_credit_sent_ms_ = 0;
    credit_blocked_since_ms_ = 0;
    last_credit_req_ms_ = 0;
    receiver_pressure_dirty_ = true;
    pending_credit_reason_ = CreditControlReason::NONE;
    last_resource_nack_code_ = UET_TRIMMED;
    last_resource_nack_psn_ = 0;
    last_resource_nack_payload_ = 0;
    last_resource_nack_ms_ = 0;
    request_terminalized_keys_.clear();
    sender_terminalized_keys_.clear();
    read_response_terminalized_keys_.clear();
}
