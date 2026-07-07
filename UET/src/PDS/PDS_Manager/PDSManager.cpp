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

#include "PDSManager.hpp"

#include "PDSManagerInternal.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>

namespace {

struct RudRuntimeStatsStore
{
    mutable std::mutex mu;
    RudRuntimeStats stats;
    int64_t rate_epoch_sec{-1};
};

RudRuntimeStatsStore &runtimeStatsStore()
{
    static RudRuntimeStatsStore store;
    return store;
}

int64_t currentRateSecond()
{
    using namespace std::chrono;
    return duration_cast<seconds>(steady_clock::now().time_since_epoch()).count();
}

void rotateRateWindowLocked(RudRuntimeStatsStore &store, int64_t now_sec)
{
    if (store.rate_epoch_sec == now_sec) {
        return;
    }
    store.rate_epoch_sec = now_sec;
    store.stats.ctrl_ack_req_last_1s = 0;
    store.stats.ctrl_sack_last_1s = 0;
    store.stats.ctrl_nack_last_1s = 0;
    store.stats.ctrl_nack_resource_last_1s = 0;
    store.stats.ctrl_nack_loss_last_1s = 0;
    store.stats.retry_rc_no_match_last_1s = 0;
    store.stats.retry_terminalized_last_1s = 0;
    store.stats.read_response_terminalized_last_1s = 0;
    store.stats.ack_ctrl_ext_last_1s = 0;
    store.stats.credit_refresh_last_1s = 0;
    store.stats.credit_req_last_1s = 0;
    store.stats.credit_gate_blocked_last_1s = 0;
}

template <typename T>
bool popLocalQueue(std::queue<T> &queue, std::mutex &mutex, T &out)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (queue.empty()) {
        return false;
    }
    out = queue.front();
    queue.pop();
    return true;
}

void enqueuePdsError(std::queue<PDS_SES_error> &queue,
                     std::mutex &mutex,
                     int &event_cnt,
                     PDS_SES_error error)
{
    ++event_cnt;
    std::lock_guard<std::mutex> lock(mutex);
    queue.push(error);
}

uint16_t extractResponseMsgId(const SES_PDS_rsp &tx)
{
    switch (tx.rsp.bth_type) {
        case Semantic_Response_Header:
            return tx.rsp.bth_header.Semantic_Response_Header.message_id;
        case Semantic_Response_with_Data_Header:
            return tx.rsp.bth_header.Semantic_Response_with_Data_Header.read_request_msg_id;
        case Optimized_Response_with_Data_Header:
            return static_cast<uint16_t>(tx.rsp.bth_header.Optimized_Response_with_Data_Header.original_request_psn);
        default:
            return 0;
    }
}

} // namespace

RudBitmapPoolHandle RudResourcePool::acquireArrivalBlock(uint32_t block_base)
{
    std::lock_guard<std::mutex> lock(mu_);
    RudBitmapPoolHandle handle;
    std::unique_ptr<RudBitmapBlock> block;
    if (!free_bitmap_blocks_.empty()) {
        block = std::move(free_bitmap_blocks_.back());
        free_bitmap_blocks_.pop_back();
    } else if (bitmap_blocks_total_ < max_bitmap_blocks_) {
        block = std::make_unique<RudBitmapBlock>();
        ++bitmap_blocks_total_;
    } else {
        ++arrival_alloc_failures_;
        return handle;
    }

    block->base_index = block_base;
    block->received_bits = 0;
    block->received_count = 0;
    block->full = false;
    handle.block_base = block_base;
    handle.block = std::move(block);
    ++bitmap_blocks_in_use_;
    bitmap_blocks_peak_ = std::max(bitmap_blocks_peak_, bitmap_blocks_in_use_);
    return handle;
}

void RudResourcePool::releaseArrivalBlock(RudBitmapPoolHandle &handle)
{
    if (!handle.block) {
        return;
    }
    std::lock_guard<std::mutex> lock(mu_);
    handle.block->base_index = 0;
    handle.block->received_bits = 0;
    handle.block->received_count = 0;
    handle.block->full = false;
    free_bitmap_blocks_.push_back(std::move(handle.block));
    handle.block_base = 0;
    if (bitmap_blocks_in_use_ > 0) {
        --bitmap_blocks_in_use_;
    }
}

RudUnexpectedBufferHandle RudResourcePool::acquireUnexpectedBuffer(uint32_t bytes)
{
    std::lock_guard<std::mutex> lock(mu_);
    RudUnexpectedBufferHandle handle;
    if (unexpected_msgs_in_use_ >= max_unexpected_msgs_ ||
        (static_cast<size_t>(bytes) + unexpected_bytes_in_use_) > max_unexpected_bytes_) {
        ++unexpected_alloc_failures_;
        return handle;
    }

    handle.capacity = bytes;
    if (bytes > 0) {
        handle.bytes = std::make_unique<uint8_t[]>(bytes);
        if (!handle.bytes) {
            ++unexpected_alloc_failures_;
            handle.capacity = 0;
            return handle;
        }
        std::memset(handle.bytes.get(), 0, bytes);
    }
    ++unexpected_msgs_in_use_;
    unexpected_msgs_peak_ = std::max(unexpected_msgs_peak_, unexpected_msgs_in_use_);
    unexpected_bytes_in_use_ += bytes;
    unexpected_bytes_peak_ = std::max(unexpected_bytes_peak_, unexpected_bytes_in_use_);
    return handle;
}

void RudResourcePool::releaseUnexpectedBuffer(RudUnexpectedBufferHandle &handle)
{
    if (handle.capacity == 0 && !handle.bytes) {
        return;
    }
    std::lock_guard<std::mutex> lock(mu_);
    if (unexpected_msgs_in_use_ > 0) {
        --unexpected_msgs_in_use_;
    }
    if (unexpected_bytes_in_use_ >= handle.capacity) {
        unexpected_bytes_in_use_ -= handle.capacity;
    } else {
        unexpected_bytes_in_use_ = 0;
    }
    handle.bytes.reset();
    handle.capacity = 0;
}

void RudResourcePool::configure(size_t max_bitmap_blocks, size_t max_unexpected_msgs, size_t max_unexpected_bytes)
{
    std::lock_guard<std::mutex> lock(mu_);
    max_bitmap_blocks_ = max_bitmap_blocks;
    max_unexpected_msgs_ = max_unexpected_msgs;
    max_unexpected_bytes_ = max_unexpected_bytes;
}

RudResourceStats RudResourcePool::stats() const
{
    std::lock_guard<std::mutex> lock(mu_);
    RudResourceStats s{};
    s.arrival_blocks_in_use = bitmap_blocks_in_use_;
    s.arrival_blocks_peak = bitmap_blocks_peak_;
    s.arrival_alloc_failures = arrival_alloc_failures_;
    s.max_bitmap_blocks = max_bitmap_blocks_;
    s.bitmap_blocks_in_use = bitmap_blocks_in_use_;
    s.bitmap_blocks_available =
        (max_bitmap_blocks_ > bitmap_blocks_in_use_) ? (max_bitmap_blocks_ - bitmap_blocks_in_use_) : 0u;
    s.unexpected_msgs_in_use = unexpected_msgs_in_use_;
    s.max_unexpected_msgs = max_unexpected_msgs_;
    s.unexpected_msgs_peak = unexpected_msgs_peak_;
    s.unexpected_bytes_in_use = unexpected_bytes_in_use_;
    s.max_unexpected_bytes = max_unexpected_bytes_;
    s.unexpected_bytes_available =
        (max_unexpected_bytes_ > unexpected_bytes_in_use_) ? (max_unexpected_bytes_ - unexpected_bytes_in_use_) : 0u;
    s.unexpected_bytes_peak = unexpected_bytes_peak_;
    s.unexpected_alloc_failures = unexpected_alloc_failures_;
    return s;
}

RudResourcePool &sharedRudResourcePool()
{
    static RudResourcePool pool;
    return pool;
}

void configureSharedRudResourcePool(size_t max_bitmap_blocks, size_t max_unexpected_msgs, size_t max_unexpected_bytes)
{
    sharedRudResourcePool().configure(max_bitmap_blocks, max_unexpected_msgs, max_unexpected_bytes);
}

RudResourceStats getSharedRudResourceStats()
{
    return sharedRudResourcePool().stats();
}

RudRuntimeStats getRudRuntimeStats()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    return store.stats;
}

void resetRudRuntimeStats()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    store.stats = RudRuntimeStats{};
    store.rate_epoch_sec = currentRateSecond();
}

void setRudActiveRetryStates(size_t active_states)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    store.stats.active_retry_states = active_states;
}

void noteRudRetryScheduled()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.retry_scheduled;
}

void noteRudRcNoMatchRetryScheduled()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.retry_rc_no_match_scheduled;
    ++store.stats.retry_rc_no_match_last_1s;
}

void noteRudRetryFired()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.retry_fired;
}

void noteRudRetryGiveup()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.retry_giveups;
}

void noteRudRetryTerminalized(SenderTerminalReason reason)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    switch (reason) {
        case SenderTerminalReason::RTO_EXHAUSTED:
            ++store.stats.retry_terminalized_by_rto_exhaust;
            break;
        case SenderTerminalReason::CLOSE_RESET:
            ++store.stats.retry_terminalized_by_close_reset;
            break;
        case SenderTerminalReason::TEARDOWN_ORPHAN:
            ++store.stats.retry_terminalized_by_teardown_orphan;
            break;
    }
    ++store.stats.retry_terminalized_last_1s;
}

void noteRudRetryStateOrphanCleanup()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.retry_state_orphan_cleanups;
}

void noteRudRetryTerminalDuplicateIgnored()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.retry_terminal_duplicates_ignored;
}

void setRudActiveReadResponseStates(size_t active_states)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    store.stats.active_read_response_states = active_states;
}

void noteRudReadResponseTerminalized(ReadResponseTerminalReason reason)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    switch (reason) {
        case ReadResponseTerminalReason::RTO_EXHAUSTED:
            ++store.stats.read_response_terminalized_by_rto_exhaust;
            break;
        case ReadResponseTerminalReason::CLOSE_RESET:
            ++store.stats.read_response_terminalized_by_close_reset;
            break;
        case ReadResponseTerminalReason::TEARDOWN_ORPHAN:
            ++store.stats.read_response_terminalized_by_teardown_orphan;
            break;
    }
    ++store.stats.read_response_terminalized_last_1s;
}

void noteRudReadResponseOrphanCleanup()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.read_response_orphan_cleanups;
}

void noteRudReadResponseTerminalDuplicateIgnored()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.read_response_terminal_duplicates_ignored;
}

void noteRudCtrlAckReqSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_ack_req_sent;
    ++store.stats.ctrl_ack_req_last_1s;
}

void noteRudCtrlAckReqSuppressed()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_ack_req_suppressed;
}

void noteRudCtrlSackSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_sack_sent;
    ++store.stats.ctrl_sack_last_1s;
}

void noteRudCtrlSackSuppressed()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_sack_suppressed;
}

void noteRudCtrlNackSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_nack_sent;
    ++store.stats.ctrl_nack_last_1s;
}

void noteRudCtrlNackSentByClass(uint8_t nack_class)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    switch (nack_class) {
        case 0:
            ++store.stats.ctrl_nack_fatal_sent;
            break;
        case 1:
            ++store.stats.ctrl_nack_resource_sent;
            ++store.stats.ctrl_nack_resource_last_1s;
            break;
        case 2:
            ++store.stats.ctrl_nack_loss_sent;
            ++store.stats.ctrl_nack_loss_last_1s;
            break;
        default:
            break;
    }
}

void noteRudCtrlNackSuppressed()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_nack_suppressed;
}

void noteRudCtrlNackSuppressedByClass(uint8_t nack_class)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    switch (nack_class) {
        case 1:
            ++store.stats.ctrl_nack_resource_suppressed;
            break;
        case 2:
            ++store.stats.ctrl_nack_loss_suppressed;
            break;
        default:
            break;
    }
}

void noteRudCtrlBudgetDeferred()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_budget_deferred;
}

void noteRudCtrlBudgetDeferredByClass(bool class_b)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_budget_deferred;
    if (class_b) {
        ++store.stats.ctrl_budget_class_b_deferred;
    } else {
        ++store.stats.ctrl_budget_class_c_deferred;
    }
}

void noteRudCtrlGapNackSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_gap_nack_sent;
}

void noteRudCtrlGapNackSuppressed()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ctrl_gap_nack_suppressed;
}

void noteRudAckCtrlExtSent(bool sack_present,
                           bool credit_present,
                           bool ackreq_hint_present,
                           bool receiver_pressure_present)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.ack_ctrl_ext_sent;
    ++store.stats.ack_ctrl_ext_last_1s;
    if (sack_present) {
        ++store.stats.ack_sack_piggyback_sent;
    }
    if (credit_present) {
        ++store.stats.ack_credit_piggyback_sent;
    }
    if (ackreq_hint_present) {
        ++store.stats.ack_ackreq_hint_piggyback_sent;
    }
    if (receiver_pressure_present) {
        ++store.stats.ack_receiver_pressure_piggyback_sent;
    }
}

void noteRudCreditCpSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_cp_sent;
}

void noteRudCreditRefreshSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_refresh_sent;
    ++store.stats.credit_refresh_last_1s;
}

void noteRudCreditRefreshSuppressed()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_refresh_suppressed;
}

void noteRudCreditReqSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_req_sent;
    ++store.stats.credit_req_last_1s;
}

void noteRudCreditResyncReqSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_resync_req_sent;
}

void noteRudCreditResyncRspSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_resync_rsp_sent;
}

void noteRudCreditResyncSuccess()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_resync_success;
}

void noteRudCreditResyncTimeout()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_resync_timeout;
}

void noteRudCreditUpdateRx()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_updates_rx;
}

void noteRudCreditStaleIgnored()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_stale_ignored;
}

void noteRudCreditGateBlocked()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.credit_gate_blocked;
    ++store.stats.credit_gate_blocked_last_1s;
}

void noteRudPiggybackPromoted()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.piggyback_promoted;
}

void noteRudStandaloneFallbackSent()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.standalone_fallback_sent;
}

void noteRudUnexpectedAllocated()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.unexpected_buffered_in_use;
    ++store.stats.unexpected_partial_in_use;
}

void noteRudUnexpectedSemanticAccepted()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    if (store.stats.unexpected_partial_in_use > 0) {
        --store.stats.unexpected_partial_in_use;
    }
    ++store.stats.unexpected_semantic_accepted_in_use;
}

void noteRudUnexpectedMatched()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.unexpected_match_count;
}

void noteRudUnexpectedReleased(bool semantic_accepted, bool due_close_reset, uint64_t residence_ms)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    if (store.stats.unexpected_buffered_in_use > 0) {
        --store.stats.unexpected_buffered_in_use;
    }
    if (semantic_accepted) {
        if (store.stats.unexpected_semantic_accepted_in_use > 0) {
            --store.stats.unexpected_semantic_accepted_in_use;
        }
    } else if (store.stats.unexpected_partial_in_use > 0) {
        --store.stats.unexpected_partial_in_use;
    }
    if (due_close_reset) {
        ++store.stats.unexpected_close_reset_cleanups;
    }
    store.stats.unexpected_max_buffered_residence_ms =
        std::max(store.stats.unexpected_max_buffered_residence_ms, residence_ms);
}

void noteRudUnexpectedPartialTimeoutCleanup()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.unexpected_partial_timeout_cleanups;
}

void noteRudArrivalBlockReleased(size_t count)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    store.stats.arrival_block_release_count += count;
}

void noteRudDuplicateBeforeEpsn()
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    ++store.stats.duplicate_before_epsn_hits;
}

void noteRudCompletionSuccess(PDC_RX_completion_type type, PDC_RX_completion_notify_kind notify_kind)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    switch (type) {
        case PDC_RX_completion_type::WRITE:
            ++store.stats.write_complete_success;
            break;
        case PDC_RX_completion_type::READ_RESPONSE:
            ++store.stats.read_response_complete_success;
            break;
        case PDC_RX_completion_type::SEND:
            if (notify_kind == PDC_RX_completion_notify_kind::SEMANTIC_ACCEPT ||
                notify_kind == PDC_RX_completion_notify_kind::OP_COMPLETE) {
                ++store.stats.send_semantic_accept_success;
            }
            if (notify_kind == PDC_RX_completion_notify_kind::TARGET_DELIVERY_COMPLETE ||
                notify_kind == PDC_RX_completion_notify_kind::OP_COMPLETE) {
                ++store.stats.send_target_delivery_complete_success;
            }
            break;
        default:
            break;
    }
}

void noteRudFailureBucket(RudFailureBucket bucket)
{
    auto &store = runtimeStatsStore();
    std::lock_guard<std::mutex> lock(store.mu);
    rotateRateWindowLocked(store, currentRateSecond());
    switch (bucket) {
        case RudFailureBucket::RC_NO_MATCH:
            ++store.stats.failure_rc_no_match;
            break;
        case RudFailureBucket::RC_PARTIAL_WRITE:
            ++store.stats.failure_rc_partial_write;
            break;
        case RudFailureBucket::RC_PROTOCOL_ERROR:
            ++store.stats.failure_rc_protocol_error;
            break;
        case RudFailureBucket::RC_NO_BUFFER:
            ++store.stats.failure_rc_no_buffer;
            break;
        case RudFailureBucket::UET_NO_BITMAP:
            ++store.stats.failure_uet_no_bitmap;
            break;
    }
}

bool PDS_Manager::initPDSM()
{
    LOG_INFO(__FUNCTION__, "=====================PDS Manager State Machine Initialization=====================");
    LOG_INFO(__FUNCTION__, "Creating PDC process managers");

    if (!TPDC_Processmanager.start() || !IPDC_Processmanager.start()) {
        LOG_ERROR(__FUNCTION__, "PDC process manager initialization failed");
    } else {
        LOG_INFO(__FUNCTION__, "PDC process manager initialization successful");
    }

    PDStoNet.set_max_size(1024);
    PDCtoSES_req.set_max_size(512);
    PDCtoSES_rsp.set_max_size(512);
    LOG_INFO(__FUNCTION__, "Public queue initialization completed");

    TPDC_Processmanager.setPublicQueues(&PDStoNet, &PDCtoSES_req, &PDCtoSES_rsp, &PDC_close_q);
    IPDC_Processmanager.setPublicQueues(&PDStoNet, &PDCtoSES_req, &PDCtoSES_rsp, &PDC_close_q);
    LOG_INFO(__FUNCTION__, "Public queue references passed to process managers");

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    open_cnt = 0;
    pend_cnt = 0;
    closing_cnt = 0;
    event_cnt = 0;
    pause_ses = false;

    LOG_INFO(__FUNCTION__, "=====================PDS Manager State Machine Initialization Completed=====================");
    return true;
}

void PDS_Manager::mainChk()
{
    bool has_eager = false;
    bool has_ses_rsp = false;
    bool has_net_pkt = false;
    bool has_ses_req = false;
    {
        std::lock_guard<std::mutex> lock(local_queue_mutex_);
        has_eager = !SES_eager_req_q.empty();
        has_ses_rsp = !SES_tx_rsp_q.empty();
        has_net_pkt = !Net_rx_pkt_q.empty();
        has_ses_req = !SES_tx_req_q.empty();
    }

    if (has_eager) {
        return;
    }
    if (has_ses_rsp) {
        LOG_INFO(__FUNCTION__, "Processing SES load response");
        sesTxRsp();
    } else if (has_net_pkt) {
        LOG_INFO(__FUNCTION__, "Processing network layer packet reception");
        rxPkt();
    } else if (has_ses_req) {
        LOG_INFO(__FUNCTION__, "Processing SES load request");
        SESTxReq();
    } else if (!PDC_close_q.empty()) {
        LOG_INFO(__FUNCTION__, "Processing PDC close request");
        PDCClose();
    }
}

void PDS_Manager::sesTxRsp()
{
    LOG_INFO("ses_tx_rsp", "=====================处理SES TX响应=====================");
    SES_PDS_rsp tx{};
    if (!popLocalQueue(SES_tx_rsp_q, local_queue_mutex_, tx)) {
        return;
    }

    const uint16_t pdc_id = tx.PDCID;
    const uint16_t msg_id = extractResponseMsgId(tx);
    if (assignPDC(msg_id, pdc_id)) {
        LOG_INFO("ses_tx_rsp", "为TX_RSP分配PDC，ID: " + std::to_string(pdc_id));
        fwdPkt2PDC(&tx, pdc_id);
        return;
    }

    LOG_ERROR("ses_tx_rsp", "Cannot allocate PDC, dropping packet");
    enqueuePdsError(PDS_error_q,
                    local_queue_mutex_,
                    event_cnt,
                    PDS_SES_error{PDS_SES_Error_Unknown, tx.rx_pkt_handle});
    LOG_WARN("ses_tx_rsp",
             "创建错误事件，类型: " + std::to_string(PDS_SES_Error_Unknown) +
                 "，事件计数: " + std::to_string(event_cnt));
}

void PDS_Manager::sendNack(PDStoNET_pkt *rx, PDS_Nack_Codes nack_type)
{
    PDStoNET_pkt nack_pkt{};
    nack_pkt.src_fep = rx->dst_fep;
    nack_pkt.dst_fep = rx->src_fep;
    nack_pkt.PDS_type = PDS_header_type::nack_header;
    nack_pkt.SESpkt = {};
    nack_pkt.PDS_header.nack_header.type = PDS_type::NACK;
    nack_pkt.PDS_header.nack_header.next_hdr = PDS_next_hdr::UET_HDR_NONE;
    nack_pkt.PDS_header.nack_header.flags.m = 0;
    nack_pkt.PDS_header.nack_header.flags.retx = 0;
    nack_pkt.PDS_header.nack_header.flags.nt = 0;
    nack_pkt.PDS_header.nack_header.nack_code = nack_type;
    nack_pkt.PDS_header.nack_header.vendor_code = 0;
    nack_pkt.PDS_header.nack_header.nack_psn = rx->PDS_header.RUOD_req_header.psn;
    nack_pkt.PDS_header.nack_header.spdcid = rx->PDS_header.RUOD_req_header.dpdcid;
    nack_pkt.PDS_header.nack_header.dpdcid = rx->PDS_header.RUOD_req_header.spdcid;
    nack_pkt.PDS_header.nack_header.payload = 0;
    PDStoNet.push(nack_pkt);
    LOG_INFO("send_nack", "Sending NACK packet, NACK type: " + std::to_string(nack_type));
}

void PDS_Manager::SESTxReq()
{
    LOG_INFO("ses_tx_req", "=====================处理SES TX请求=====================");
    SES_PDS_req tx{};
    if (!popLocalQueue(SES_tx_req_q, local_queue_mutex_, tx)) {
        return;
    }
    std::cout << "[uet-pds] SESTxReq pop msg_id="
              << tx.pkt.bth_header.Standard_Header.msg_id
              << " job_id=" << tx.pkt.bth_header.Standard_Header.job_id
              << " src_fep=" << tx.src_fep
              << " dst_fep=" << tx.dst_fep
              << " mode=" << static_cast<unsigned>(tx.mode)
              << " tc=" << static_cast<unsigned>(tx.tc)
              << std::endl;

    uint16_t pdc_id = 0;
    if (assignPDC(tx.pkt.bth_header.Standard_Header.job_id,
                  tx.dst_fep,
                  tx.tc,
                  tx.mode,
                  tx.pkt.bth_header.Standard_Header.msg_id,
                  &pdc_id)) {
        if (!PDCOpen(pdc_id) && !isOOR()) {
            const AllocPDCResult alloc_result = allocPDC(pdc_id, tx.dst_fep, tx.src_fep, tx.mode);
            if (alloc_result == AllocPDCResult::CREATED) {
                LOG_INFO("ses_tx_req",
                         "PDC allocation successful, ID: " + std::to_string(pdc_id) +
                             ", current open count: " + std::to_string(open_cnt));
                bindPdc(pdc_id, tx.src_fep, tx.dst_fep, 0, tx.mode);
            } else if (alloc_result == AllocPDCResult::ALREADY_OPEN) {
                LOG_INFO("ses_tx_req", "PDC already open, reusing ID: " + std::to_string(pdc_id));
            } else {
                LOG_ERROR("ses_tx_req", "Unexpected error: PDC allocation failed");
            }
        }
        if (isOOR()) {
            txOORPendEnqueue(&tx);
        } else {
            std::cout << "[uet-pds] SESTxReq forward pdc_id=" << pdc_id << std::endl;
            fwdPkt2PDC(&tx, pdc_id);
        }
    } else {
        std::cout << "[uet-pds] SESTxReq assignPDC failed" << std::endl;
        LOG_WARN("ses_tx_req", "PDC cannot be allocated, entering TX OOR & PEND queue");
        txOORPendEnqueue(&tx);
    }
}

bool PDS_Manager::isOOR()
{
    return open_cnt >= MAX_PDC;
}

bool PDS_Manager::PDCOpen(int pdc_id)
{
    if (pdc_id < 0 || pdc_id >= MAX_PDC * 2) {
        LOG_ERROR("pdc_open", "PDC ID " + std::to_string(pdc_id) + " out of range");
        return false;
    }
    if (!pdc_list[pdc_id].is_open) {
        LOG_ERROR("pdc_open", "PDC ID " + std::to_string(pdc_id) + " not open");
        return false;
    }
    return true;
}

void PDS_Manager::txOORPendEnqueue(SES_PDS_req *tx)
{
    LOG_INFO("tx_oor_pend_enqueue", "=====================TX OOR & PEND Request Enqueue=====================");
    pend_node node = createPendNode(*tx);
    pend_q.push(node);
    pend_cnt++;
    if (pendQFull()) {
        pause_ses = true;
        LOG_WARN("tx_oor_pend_enqueue", "Wait queue is full, SES paused");
    }
    resourceCheck();
}

bool PDS_Manager::pendQFull()
{
    return pend_cnt >= MAX_PEND;
}

pend_node PDS_Manager::createPendNode(SES_PDS_req tx)
{
    LOG_INFO("create_pend_node", "=====================Creating Wait Node=====================");
    const auto pend_start = std::chrono::steady_clock::now();
    const uint32_t pend_start_ms = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(pend_start.time_since_epoch()).count());
    const uint32_t pend_time = Pend_Time;
    const auto pend_end = pend_start + std::chrono::milliseconds(pend_time);
    const uint32_t pend_end_ms = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(pend_end.time_since_epoch()).count());
    LOG_INFO("create_pend_node", "Wait start time: " + std::to_string(pend_start_ms));
    LOG_INFO("create_pend_node", "Wait end time: " + std::to_string(pend_end_ms));
    return {tx, pend_time, pend_start_ms, pend_end_ms};
}

void PDS_Manager::fwdPkt2PDC(struct SES_PDS_req *pkt, int pdc_id)
{
    LOG_INFO("fwd_pkt_to_pdc", "转发数据包类型: SES_PDS_req");
    LOG_INFO("fwd_pkt_to_pdc", "转发数据包到PDC ID: " + std::to_string(pdc_id));
    PDS_PDC_req req = {};
    req.next_hdr = pkt->next_hdr;
    req.tx_pkt_handle = pkt->tx_pkt_handle;
    req.pkt = pkt->pkt;
    req.pkt_len = pkt->pkt_len;
    req.is_retry = pkt->is_retry;
    req.som = (pkt->pkt.bth_header.Standard_Header.som != 0);
    req.eom = (pkt->pkt.bth_header.Standard_Header.eom != 0);

    if (pdc_id < MAX_PDC) {
        IPDC_Processmanager.pushTxRequest(pdc_id, req);
    } else {
        TPDC_Processmanager.pushTxRequest(pdc_id, req);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    resourceCheck();
}

void PDS_Manager::fwdPkt2PDC(struct SES_PDS_rsp *pkt, int pdc_id)
{
    LOG_INFO("fwd_pkt_to_pdc", "转发数据包类型: SES_PDS_rsp");
    LOG_INFO("fwd_pkt_to_pdc", "转发数据包到PDC ID: " + std::to_string(pdc_id));
    SES_PDC_rsp rsp = {};
    rsp.rx_pkt_handle = pkt->rx_pkt_handle;
    rsp.gtd_del = pkt->gtd_del;
    rsp.ses_nack = pkt->ses_nack;
    rsp.nack_payload = pkt->nack_payload;
    rsp.pkt = pkt->rsp;
    rsp.rep_len = pkt->rsp_len;

    if (pdc_id < MAX_PDC) {
        IPDC_Processmanager.pushTxResponse(pdc_id, rsp);
    } else {
        TPDC_Processmanager.pushTxResponse(pdc_id, rsp);
    }
    resourceCheck();
}

void PDS_Manager::fwdPkt2PDC(struct PDStoNET_pkt *pkt, int pdc_id)
{
    LOG_INFO("fwd_pkt_to_pdc", "转发数据包类型: PDStoNET_pkt");
    LOG_INFO("fwd_pkt_to_pdc", "Forwarding packet to PDC ID: " + std::to_string(pdc_id));
    if (pdc_id < MAX_PDC) {
        IPDC_Processmanager.pushRxPacket(pdc_id, *pkt);
    } else {
        TPDC_Processmanager.pushRxPacket(pdc_id, *pkt);
    }
    resourceCheck();
}

void PDS_Manager::pendTimeOut(pend_node node)
{
    LOG_WARN("pend_timeout", "Processing timed out wait node");
    pend_cnt--;
    event_cnt++;
    dropPkt(node);
    sendError2SES();
}

void PDS_Manager::sendError2SES()
{
    LOG_INFO("send_error_to_ses", "Sending error message to SES");
}

void PDS_Manager::dropPkt(pend_node node)
{
    LOG_DEBUG("drop_packet", "node :" + std::to_string(node.tx_req.pkt.bth_header.Standard_Header.msg_id) + " dropped");
}

bool PDS_Manager::isPendNodeOverTime(pend_node node)
{
    const auto pend_end = std::chrono::steady_clock::now();
    const uint32_t time_now_ms = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(pend_end.time_since_epoch()).count());
    return time_now_ms > node.end_time;
}

PDS_Manager::PDC_TYPE PDS_Manager::getPDCType(int pdc_id)
{
    if (pdc_id < MAX_PDC) {
        return PDS_Manager::PDC_TYPE::IPDC;
    }
    return PDS_Manager::PDC_TYPE::TPDC;
}

bool PDS_Manager::pdsError()
{
    LOG_DEBUG("pds_error", "PDC error");
    return true;
}
