#include "PDC_RudInternals.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

std::mutex g_unexpected_send_registry_mu;
std::list<UnexpectedSendRegistryEntry> g_unexpected_send_registry;
std::mutex g_request_tx_registry_mu;
std::list<RequestTxRegistryEntry> g_request_tx_registry;

UnexpectedSendProbe PDC::buildUnexpectedSendProbe(const RxMessageContext &ctx)
{
    UnexpectedSendProbe probe{};
    probe.present = ctx.unexpected != nullptr;
    probe.send_mode = ctx.send_mode;
    probe.completed = ctx.completed;
    probe.failed = ctx.failed;
    probe.chunks_done = ctx.chunks_done;
    probe.expected_chunks = ctx.expected_chunks;
    if (ctx.unexpected) {
        probe.semantic_accepted = ctx.unexpected->semantic_accepted;
        probe.buffered_complete = ctx.unexpected->buffered_complete;
        probe.matched_to_recv = ctx.unexpected->matched_to_recv;
        probe.last_activity_ms = ctx.unexpected->last_activity_ms;
    }
    return probe;
}

UnexpectedSendProbe PDC::queryUnexpectedSendProbe(uint64_t job_id, uint16_t msg_id, uint32_t src_fep)
{
    std::lock_guard<std::mutex> lock(g_unexpected_send_registry_mu);
    for (const auto &entry : g_unexpected_send_registry) {
        if (!entry.owner ||
            entry.job_id != job_id ||
            entry.src_fep != src_fep ||
            entry.key.msg_id != msg_id) {
            continue;
        }
        auto it = entry.owner->rud_rx_messages_.find(entry.key);
        if (it == entry.owner->rud_rx_messages_.end()) {
            continue;
        }
        return buildUnexpectedSendProbe(it->second);
    }
    return UnexpectedSendProbe{};
}

RequestTxProbe PDC::buildRequestTxProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep) const
{
    RequestTxProbe probe{};
    probe.last_tx_progress_ms = last_activity_ms.load(std::memory_order_relaxed);
    bool saw_control = false;
    bool saw_data = false;

    for (const auto &entry : tx_pkt_map) {
        const uint32_t psn = entry.first;
        const TX_pkt_meta &meta = entry.second;
        if (meta.job_id != job_id || meta.msg_id != msg_id || meta.dst_fep != dst_fep) {
            continue;
        }
        probe.present = true;
        probe.has_tx_pkt_map_entries = true;
        ++probe.pending_psn_count;
        if (probe.oldest_pending_psn == 0 || psn < probe.oldest_pending_psn) {
            probe.oldest_pending_psn = psn;
        }
        const bool is_data = meta.is_request_som || meta.is_read_response_data;
        saw_data = saw_data || is_data;
        saw_control = saw_control || !is_data;
    }

    for (const auto &entry : tx_pkt_buffer) {
        const uint32_t psn = entry.first;
        const TX_pkt_meta *meta = nullptr;
        auto meta_it = tx_pkt_map.find(psn);
        if (meta_it != tx_pkt_map.end()) {
            meta = &meta_it->second;
        }
        if (!meta || meta->job_id != job_id || meta->msg_id != msg_id || meta->dst_fep != dst_fep) {
            continue;
        }
        probe.present = true;
        probe.has_tx_pkt_buffer_entries = true;
    }

    probe.pending_control_only = probe.present && saw_control && !saw_data;
    probe.pending_data_only = probe.present && saw_data && !saw_control;
    return probe;
}

RequestTxProbe PDC::queryRequestTxProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep)
{
    std::lock_guard<std::mutex> lock(g_request_tx_registry_mu);
    for (const auto &entry : g_request_tx_registry) {
        if (!entry.owner ||
            entry.job_id != job_id ||
            entry.msg_id != msg_id ||
            entry.dst_fep != dst_fep) {
            continue;
        }
        return entry.owner->buildRequestTxProbe(job_id, msg_id, dst_fep);
    }
    return RequestTxProbe{};
}

bool PDC::matchUnexpectedSend(uint64_t job_id,
                              uint16_t pdc_id,
                              uint32_t src_fep,
                              uint64_t completion_key,
                              uint64_t base_addr,
                              uint32_t buffer_len)
{
    PDC *owner = nullptr;
    RxMessageKey key{};
    {
        std::lock_guard<std::mutex> lock(g_unexpected_send_registry_mu);
        for (auto it = g_unexpected_send_registry.begin(); it != g_unexpected_send_registry.end(); ++it) {
            if (it->job_id != job_id || it->src_fep != src_fep) {
                continue;
            }
            if (pdc_id != 0 && it->pdcid != pdc_id) {
                continue;
            }
            owner = it->owner;
            key = it->key;
            g_unexpected_send_registry.erase(it);
            break;
        }
    }
    if (!owner) {
        return false;
    }
    return owner->bindUnexpectedSend(key, completion_key, base_addr, buffer_len);
}

void PDC::copyArrivedSendChunks(const RxMessageContext &ctx, uint8_t *dst) const
{
    if (!dst || !ctx.unexpected || !ctx.unexpected->buffer.data() || ctx.chunk_payload_size == 0) {
        return;
    }
    for (uint32_t chunk_idx = 0; chunk_idx < ctx.expected_chunks; ++chunk_idx) {
        if (!isChunkArrived(ctx, chunk_idx)) {
            continue;
        }
        const uint32_t msg_off = chunk_idx * ctx.chunk_payload_size;
        const uint32_t copy_len = std::min(ctx.chunk_payload_size, ctx.total_len - msg_off);
        std::memcpy(dst + msg_off, ctx.unexpected->buffer.data() + msg_off, copy_len);
    }
}

bool PDC::bindUnexpectedSend(const RxMessageKey &key, uint64_t completion_key, uint64_t base_addr, uint32_t buffer_len)
{
    auto it = rud_rx_messages_.find(key);
    if (it == rud_rx_messages_.end()) {
        return false;
    }

    RxMessageContext &ctx = it->second;
    if (ctx.send_mode != RudSendPlacementMode::UNEXPECTED_BUFFERED || !ctx.unexpected || ctx.failed || ctx.completed) {
        return false;
    }

    if (ctx.total_len > 0 && base_addr == 0) {
        completeRxMessage(key,
                          ctx,
                          PDC_RX_completion_type::SEND,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_BUFFER),
                          false,
                          PDC_RX_completion_notify_kind::TARGET_DELIVERY_COMPLETE,
                          0);
        return true;
    }

    if (buffer_len < ctx.total_len) {
        completeRxMessage(key,
                          ctx,
                          PDC_RX_completion_type::SEND,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_PARTIAL_WRITE),
                          false,
                          PDC_RX_completion_notify_kind::TARGET_DELIVERY_COMPLETE,
                          0);
        return true;
    }

    uint8_t *dst = reinterpret_cast<uint8_t *>(base_addr);
    copyArrivedSendChunks(ctx, dst);
    ctx.placement.base_addr = base_addr;
    ctx.placement.buffer_offset = 0;
    ctx.placement.bounds_ok = true;
    ctx.placement.rkey_ok = true;
    if (completion_key != 0) {
        ctx.placement.completion_key = completion_key;
    }
    const uint64_t residence_ms =
        (ctx.unexpected->created_at_ms > 0 && nowMs() >= ctx.unexpected->created_at_ms)
            ? static_cast<uint64_t>(nowMs() - ctx.unexpected->created_at_ms)
            : 0;
    noteRudUnexpectedReleased(ctx.unexpected->semantic_accepted, false, residence_ms);
    sharedRudResourcePool().releaseUnexpectedBuffer(ctx.unexpected->buffer);
    noteRudUnexpectedMatched();
    ctx.unexpected->matched_to_recv = true;
    ctx.send_mode = RudSendPlacementMode::DIRECT_RECV;
    ctx.unexpected.reset();

    if ((ctx.total_len == 0 && ctx.saw_eom) ||
        (ctx.saw_eom && ctx.chunks_done == ctx.expected_chunks)) {
        completeRxMessage(key,
                          ctx,
                          PDC_RX_completion_type::SEND,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                          true,
                          PDC_RX_completion_notify_kind::TARGET_DELIVERY_COMPLETE,
                          ctx.total_len);
    }
    return true;
}

void PDC::reapUnexpectedPartialState()
{
    const int64_t now = nowMs();
    std::vector<RxMessageKey> stale_keys;
    for (const auto &entry : rud_rx_messages_) {
        const RxMessageContext &ctx = entry.second;
        if (ctx.send_mode != RudSendPlacementMode::UNEXPECTED_BUFFERED || !ctx.unexpected) {
            continue;
        }
        if (ctx.unexpected->semantic_accepted) {
            if (!ctx.unexpected->matched_to_recv &&
                (now - ctx.unexpected->last_activity_ms) >= kUnexpectedAcceptedTimeoutMs) {
                stale_keys.push_back(entry.first);
            }
            continue;
        }
        if ((now - ctx.unexpected->last_activity_ms) >= kUnexpectedPartialTimeoutMs) {
            stale_keys.push_back(entry.first);
        }
    }

    for (const auto &key : stale_keys) {
        auto it = rud_rx_messages_.find(key);
        if (it == rud_rx_messages_.end()) {
            continue;
        }
        RxMessageContext &ctx = it->second;
        if (ctx.send_mode != RudSendPlacementMode::UNEXPECTED_BUFFERED || !ctx.unexpected) {
            continue;
        }
        decPending();
        if (!ctx.unexpected->semantic_accepted ||
            !ctx.unexpected->matched_to_recv) {
            noteRudUnexpectedPartialTimeoutCleanup();
        }
        releaseRxMessageContext(key, ctx, RudReleaseReason::PARTIAL_TIMEOUT);
    }
}
