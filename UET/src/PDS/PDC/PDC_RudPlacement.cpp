#include "PDC_RudInternals.hpp"

#include <algorithm>
#include <cstring>

PDC_SES_req PDC::buildSesReq(uint16_t handle, const RX_pkt_meta &meta, const SEStoPDS_pkt &pkt) const
{
    PDC_SES_req req{};
    req.PDCID = SPDCID;
    req.rx_pkt_handle = handle;
    req.mode = static_cast<uint8_t>(mode);
    req.pkt = pkt;
    req.pkt_len = meta.payload_len;
    req.next_hdr = meta.next_hdr;
    req.src_fep = meta.src_fep;
    req.orig_psn = meta.psn;
    req.orig_pdcid = meta.spdcid;
    return req;
}

PDC_SES_rsp PDC::buildSesRsp(const PDStoNET_pkt *pkt) const
{
    PDC_SES_rsp rsp{};
    rsp.PDCID = SPDCID;
    rsp.mode = static_cast<uint8_t>(mode);
    if (!pkt) {
        return rsp;
    }
    rsp.rx_pkt_handle = const_cast<PDC *>(this)->cacheResponseHandle(pkt);
    rsp.pkt = pkt->SESpkt;
    rsp.pkt_len = static_cast<uint16_t>(pkt->SESpkt.payload.size());
    rsp.src_fep = pkt->src_fep;
    return rsp;
}

bool PDC::shouldOwnRudRequest(const PDStoNET_pkt *pkt) const
{
    if (!pkt || !isRudMode() || !hasRxCallbacks()) {
        return false;
    }
    if (pkt->PDS_type != RUOD_req_header || pkt->SESpkt.bth_type != Standard_Header) {
        return false;
    }
    return true;
}

bool PDC::shouldOwnRudResponse(const PDStoNET_pkt *pkt) const
{
    if (!pkt || !isRudMode() || !hasRxCallbacks()) {
        return false;
    }
    if (pkt->PDS_type != RUOD_ack_header) {
        return false;
    }
    const auto next_hdr = pkt->PDS_header.RUOD_ack_header.next_hdr;
    if (next_hdr != UET_HDR_RESPONSE_DATA && next_hdr != UET_HDR_RESPONSE_DATA_SMALL) {
        return false;
    }
    return pkt->SESpkt.bth_type == Semantic_Response_with_Data_Header;
}

uint32_t PDC::payloadChunkSizeForRequest(const PDC_SES_req &req) const
{
    (void)req;
    return static_cast<uint32_t>(kSesMaxMtu - sizeof(SES_Standard_Header));
}

uint32_t PDC::payloadChunkSizeForResponse(const PDC_SES_rsp &rsp) const
{
    (void)rsp;
    return static_cast<uint32_t>(kSesMaxMtu - sizeof(SES_Semantic_Response_with_Data_Header));
}

RxMessageKey PDC::buildRxMessageKey(const PDC_SES_req &req) const
{
    const auto &hdr = req.pkt.bth_header.Standard_Header;
    return RxMessageKey{
        static_cast<uint8_t>(hdr.opcode),
        hdr.job_id,
        hdr.msg_id,
        req.src_fep,
        req.PDCID,
    };
}

RxMessageKey PDC::buildRxMessageKey(const PDC_SES_rsp &rsp) const
{
    const auto &hdr = rsp.pkt.bth_header.Semantic_Response_with_Data_Header;
    return RxMessageKey{
        kReadOpcode,
        hdr.job_id,
        hdr.read_request_msg_id,
        rsp.src_fep,
        rsp.PDCID,
    };
}

uint32_t PDC::expectedChunks(uint32_t total_len, uint32_t chunk_size) const
{
    if (chunk_size == 0) {
        return 0;
    }
    return total_len == 0 ? 0 : static_cast<uint32_t>((static_cast<uint64_t>(total_len) + chunk_size - 1) / chunk_size);
}

bool PDC::ensureRxMessageContext(const PDC_SES_req &req,
                                 uint32_t base_psn,
                                 uint16_t rx_pkt_handle,
                                 RxMessageContext *&ctx_out)
{
    const RxMessageKey key = buildRxMessageKey(req);
    auto it = rud_rx_messages_.find(key);
    if (it == rud_rx_messages_.end()) {
        const RxPlacementDescriptor placement = resolve_rx_request_placement_(req);
        PDC_RX_completion_type completion_type = PDC_RX_completion_type::WRITE;
        if (req.pkt.bth_header.Standard_Header.opcode == kSendOpcode) {
            completion_type = PDC_RX_completion_type::SEND;
        }
        if (!placement.valid) {
            const bool can_buffer_unexpected_send =
                req.pkt.bth_header.Standard_Header.opcode == kSendOpcode &&
                placement.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
            if (can_buffer_unexpected_send) {
                RudUnexpectedBufferHandle unexpected =
                    sharedRudResourcePool().acquireUnexpectedBuffer(req.pkt.bth_header.Standard_Header.request_length);
                if (unexpected.capacity == req.pkt.bth_header.Standard_Header.request_length ||
                    req.pkt.bth_header.Standard_Header.request_length == 0) {
                    RxPlacementDescriptor buffered = placement;
                    buffered.base_addr = reinterpret_cast<uint64_t>(unexpected.data());
                    buffered.buffer_offset = 0;
                    buffered.bounds_ok = true;
                    buffered.rkey_ok = true;
                    buffered.valid = true;
                    buffered.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK);

                    RxMessageContext ctx;
                    ctx.ePSN = 0;
                    ctx.base_psn = base_psn;
                    ctx.total_len = buffered.total_len;
                    ctx.chunk_payload_size = buffered.chunk_payload_size;
                    ctx.expected_chunks = expectedChunks(buffered.total_len, buffered.chunk_payload_size);
                    ctx.placement = buffered;
                    ctx.rx_pkt_handle = rx_pkt_handle;
                    ctx.send_mode = RudSendPlacementMode::UNEXPECTED_BUFFERED;
                    ctx.unexpected = std::make_unique<UnexpectedSendContext>();
                    ctx.unexpected->buffer = std::move(unexpected);
                    ctx.unexpected->created_at_ms = nowMs();
                    ctx.unexpected->last_activity_ms = ctx.unexpected->created_at_ms;
                    it = rud_rx_messages_.emplace(key, std::move(ctx)).first;
                    {
                        std::lock_guard<std::mutex> lock(g_unexpected_send_registry_mu);
                        g_unexpected_send_registry.push_back(
                            UnexpectedSendRegistryEntry{this, key, key.job_id, key.pdcid, key.src_fep});
                    }
                    noteRudUnexpectedAllocated();
                    incPending();
                    ctx_out = &it->second;
                    return true;
                }
            }
            PDC_RX_completion completion{};
            completion.type = completion_type;
            completion.opcode = req.pkt.bth_header.Standard_Header.opcode;
            completion.job_id = req.pkt.bth_header.Standard_Header.job_id;
            completion.msg_id = req.pkt.bth_header.Standard_Header.msg_id;
            completion.src_fep = req.src_fep;
            completion.pdcid = req.PDCID;
            completion.rx_pkt_handle = req.rx_pkt_handle;
            completion.completion_key = placement.completion_key;
            completion.total_len = req.pkt.bth_header.Standard_Header.request_length;
            completion.return_code = placement.return_code;
            completion.success = false;
            completion.response_required = placement.response_required;
            complete_rx_operation_(completion);
            ctx_out = nullptr;
            return false;
        }

        RxMessageContext ctx;
        ctx.ePSN = 0;
        ctx.base_psn = base_psn;
        ctx.total_len = placement.total_len;
        ctx.chunk_payload_size = placement.chunk_payload_size;
        ctx.expected_chunks = expectedChunks(placement.total_len, placement.chunk_payload_size);
        ctx.placement = placement;
        ctx.rx_pkt_handle = rx_pkt_handle;
        it = rud_rx_messages_.emplace(key, std::move(ctx)).first;
        incPending();
    }
    ctx_out = &it->second;
    return true;
}

bool PDC::ensureRxMessageContext(const PDC_SES_rsp &rsp, RxMessageContext *&ctx_out)
{
    const RxMessageKey key = buildRxMessageKey(rsp);
    auto it = rud_rx_messages_.find(key);
    if (it == rud_rx_messages_.end()) {
        const RxPlacementDescriptor placement = resolve_rx_response_placement_(rsp);
        if (!placement.valid) {
            PDC_RX_completion completion{};
            completion.type = PDC_RX_completion_type::READ_RESPONSE;
            completion.opcode = kReadOpcode;
            completion.job_id = rsp.pkt.bth_header.Semantic_Response_with_Data_Header.job_id;
            completion.msg_id = rsp.pkt.bth_header.Semantic_Response_with_Data_Header.read_request_msg_id;
            completion.src_fep = rsp.src_fep;
            completion.pdcid = rsp.PDCID;
            completion.rx_pkt_handle = rsp.rx_pkt_handle;
            completion.completion_key = placement.completion_key;
            completion.total_len = rsp.pkt.bth_header.Semantic_Response_with_Data_Header.modified_length;
            completion.return_code = placement.return_code;
            completion.success = false;
            completion.response_required = false;
            complete_rx_operation_(completion);
            ctx_out = nullptr;
            return false;
        }

        RxMessageContext ctx;
        ctx.ePSN = 0;
        ctx.base_psn = 0;
        ctx.total_len = placement.total_len;
        ctx.chunk_payload_size = placement.chunk_payload_size;
        ctx.expected_chunks = expectedChunks(placement.total_len, placement.chunk_payload_size);
        ctx.placement = placement;
        ctx.rx_pkt_handle = rsp.rx_pkt_handle;
        it = rud_rx_messages_.emplace(key, std::move(ctx)).first;
    }
    ctx_out = &it->second;
    return true;
}

uint16_t PDC::cacheResponseHandle(const PDStoNET_pkt *pkt)
{
    if (!pkt || pkt->PDS_type != RUOD_ack_header) {
        return 0;
    }

    RX_pkt_meta meta{};
    meta.type = pkt->PDS_header.RUOD_ack_header.type;
    meta.next_hdr = pkt->PDS_header.RUOD_ack_header.next_hdr;
    meta.spdcid = pkt->PDS_header.RUOD_ack_header.spdcid;
    meta.src_fep = pkt->src_fep;
    meta.psn = pkt->PDS_header.RUOD_ack_header.ack_psn_off + pkt->PDS_header.RUOD_ack_header.cack_psn;
    meta.clear_psn = pkt->PDS_header.RUOD_ack_header.cack_psn;
    meta.retx = pkt->PDS_header.RUOD_ack_header.flags.retx;
    meta.payload_len = static_cast<uint16_t>(pkt->SESpkt.payload.size());

    // READ response-with-data packets all piggyback on ACK headers, so the
    // wire ACK PSN alone is not enough to distinguish reordered fragments.
    // Fold the semantic fragment offset into the cached PSN so each fragment
    // gets a stable local identity for response placement/tracking.
    if ((meta.next_hdr == UET_HDR_RESPONSE_DATA || meta.next_hdr == UET_HDR_RESPONSE_DATA_SMALL) &&
        pkt->SESpkt.bth_type == Semantic_Response_with_Data_Header) {
        const uint32_t chunk_size = static_cast<uint32_t>(
            kSesMaxMtu - sizeof(SES_Semantic_Response_with_Data_Header));
        const auto &hdr = pkt->SESpkt.bth_header.Semantic_Response_with_Data_Header;
        const uint32_t chunk_idx = (chunk_size == 0) ? 0 : (hdr.message_offset / chunk_size);
        meta.psn += chunk_idx;
    }

    const uint16_t handle = setRXhandle(meta.psn, meta.spdcid);
    rx_pkt_map[handle] = meta;
    return handle;
}

void PDC::eraseRxHandle(uint16_t handle)
{
    if (handle == 0) {
        return;
    }
    rx_pkt_map.erase(handle);
}

bool PDC::directPlaceRudWrite(PDStoNET_pkt *pkt, uint16_t handle, const RX_pkt_meta &meta)
{
    if (!shouldOwnRudRequest(pkt) || pkt->SESpkt.bth_header.Standard_Header.opcode != kWriteOpcode) {
        return false;
    }

    const PDC_SES_req req = buildSesReq(handle, meta, pkt->SESpkt);
    RxMessageContext *ctx = nullptr;
    if (!ensureRxMessageContext(req, meta.psn, handle, ctx) || !ctx) {
        return true;
    }
    const auto &hdr = req.pkt.bth_header.Standard_Header;
    const uint32_t msg_off = hdr.som ? 0 : hdr.diff.som_false.message_offset;
    const uint32_t payload_len = static_cast<uint32_t>(req.pkt.payload.size());
    const uint64_t end_off = static_cast<uint64_t>(msg_off) + static_cast<uint64_t>(payload_len);
    const RxMessageKey key = buildRxMessageKey(req);

    if (ctx->chunk_payload_size == 0) {
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::WRITE,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                          false);
        return true;
    }

    if (end_off > ctx->total_len) {
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::WRITE,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_PARTIAL_WRITE),
                          false);
        return true;
    }

    if (payload_len > 0) {
        uint8_t *dst = reinterpret_cast<uint8_t *>(ctx->placement.base_addr + ctx->placement.buffer_offset + msg_off);
        const uint8_t *src = req.pkt.payload.data();
        if (!dst || !src) {
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::WRITE,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                              false);
            return true;
        }
        std::memcpy(dst, src, payload_len);
    }

    if (ctx->total_len > 0) {
        const uint32_t chunk_idx = msg_off / ctx->chunk_payload_size;
        if (chunk_idx >= ctx->expected_chunks) {
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::WRITE,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                              false);
            return true;
        }
        switch (markChunkArrived(*ctx, chunk_idx)) {
        case ChunkArrivalResult::ALREADY_ARRIVED:
            break;
        case ChunkArrivalResult::MARKED_OK:
            break;
        case ChunkArrivalResult::NO_BITMAP:
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::WRITE,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                              false,
                              PDC_RX_completion_notify_kind::OP_COMPLETE,
                              0,
                              PDC_RX_failure_kind::PDS_NACK,
                              UET_NO_BITMAP);
            return true;
        }
    }

    if (hdr.eom) {
        ctx->saw_eom = true;
    }
    advanceMessageFrontier(*ctx);

    if ((ctx->total_len == 0 && ctx->saw_eom) ||
        (ctx->saw_eom && ctx->chunks_done == ctx->expected_chunks)) {
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::WRITE,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                          true,
                          PDC_RX_completion_notify_kind::OP_COMPLETE,
                          ctx->total_len);
    }
    return true;
}

bool PDC::directPlaceRudSend(PDStoNET_pkt *pkt, uint16_t handle, const RX_pkt_meta &meta)
{
    if (!shouldOwnRudRequest(pkt) || pkt->SESpkt.bth_header.Standard_Header.opcode != kSendOpcode) {
        return false;
    }

    const PDC_SES_req req = buildSesReq(handle, meta, pkt->SESpkt);
    const RxMessageKey key = buildRxMessageKey(req);
    if (replayCompletedSendDuplicate(key, handle)) {
        return true;
    }

    RxMessageContext *ctx = nullptr;
    if (!ensureRxMessageContext(req, meta.psn, handle, ctx) || !ctx) {
        return true;
    }

    const auto &hdr = req.pkt.bth_header.Standard_Header;
    const uint32_t msg_off = hdr.som ? 0 : hdr.diff.som_false.message_offset;
    const uint32_t payload_len = static_cast<uint32_t>(req.pkt.payload.size());
    const uint64_t end_off = static_cast<uint64_t>(msg_off) + static_cast<uint64_t>(payload_len);
    bool unexpected_progress = false;

    if (ctx->chunk_payload_size == 0) {
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::SEND,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                          false);
        return true;
    }

    if (end_off > ctx->total_len) {
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::SEND,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_PARTIAL_WRITE),
                          false);
        return true;
    }

    if (payload_len > 0) {
        uint8_t *dst = reinterpret_cast<uint8_t *>(ctx->placement.base_addr + msg_off);
        const uint8_t *src = req.pkt.payload.data();
        if (!dst || !src) {
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::SEND,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                              false);
            return true;
        }
        std::memcpy(dst, src, payload_len);
    }

    if (ctx->total_len > 0) {
        const uint32_t chunk_idx = msg_off / ctx->chunk_payload_size;
        if (chunk_idx >= ctx->expected_chunks) {
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::SEND,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                              false);
            return true;
        }
        switch (markChunkArrived(*ctx, chunk_idx)) {
        case ChunkArrivalResult::ALREADY_ARRIVED:
            break;
        case ChunkArrivalResult::MARKED_OK:
            unexpected_progress = true;
            break;
        case ChunkArrivalResult::NO_BITMAP:
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::SEND,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                              false,
                              PDC_RX_completion_notify_kind::OP_COMPLETE,
                              0,
                              PDC_RX_failure_kind::PDS_NACK,
                              UET_NO_BITMAP);
            return true;
        }
    }

    if (hdr.eom) {
        if (!ctx->saw_eom) {
            unexpected_progress = true;
        }
        ctx->saw_eom = true;
    }
    if (ctx->unexpected && unexpected_progress) {
        ctx->unexpected->last_activity_ms = nowMs();
    }
    advanceMessageFrontier(*ctx);

    if ((ctx->total_len == 0 && ctx->saw_eom) ||
        (ctx->saw_eom && ctx->chunks_done == ctx->expected_chunks)) {
        if (ctx->send_mode == RudSendPlacementMode::UNEXPECTED_BUFFERED && ctx->unexpected &&
            !ctx->unexpected->matched_to_recv) {
            ctx->unexpected->buffered_complete = true;
            if (!ctx->unexpected->semantic_accepted) {
                ctx->unexpected->semantic_accepted = true;
                noteRudUnexpectedSemanticAccepted();
                emitRxCompletion(key,
                                 *ctx,
                                 PDC_RX_completion_type::SEND,
                                 static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                                 true,
                                 PDC_RX_completion_notify_kind::SEMANTIC_ACCEPT,
                                 ctx->total_len);
            }
            return true;
        }
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::SEND,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                          true,
                          PDC_RX_completion_notify_kind::OP_COMPLETE,
                          ctx->total_len);
    }
    return true;
}

bool PDC::directPlaceRudResponse(const PDStoNET_pkt *pkt)
{
    if (!shouldOwnRudResponse(pkt)) {
        return false;
    }

    const PDC_SES_rsp rsp = buildSesRsp(pkt);
    const auto cleanup_rsp_handle = [this, &rsp]() {
        eraseRxHandle(rsp.rx_pkt_handle);
    };
    RxMessageContext *ctx = nullptr;
    if (!ensureRxMessageContext(rsp, ctx) || !ctx) {
        cleanup_rsp_handle();
        return true;
    }

    const auto &hdr = rsp.pkt.bth_header.Semantic_Response_with_Data_Header;
    const uint32_t msg_off = hdr.message_offset;
    const uint32_t payload_len = static_cast<uint32_t>(std::min<size_t>(rsp.pkt.payload.size(), hdr.payload_length));
    const uint64_t end_off = static_cast<uint64_t>(msg_off) + static_cast<uint64_t>(payload_len);
    const RxMessageKey key = buildRxMessageKey(rsp);
    const RX_pkt_meta meta = rx_pkt_map.at(rsp.rx_pkt_handle);

    if (ctx->chunk_payload_size == 0) {
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::READ_RESPONSE,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                          false);
        cleanup_rsp_handle();
        return true;
    }

    if (end_off > ctx->total_len) {
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::READ_RESPONSE,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                          false);
        cleanup_rsp_handle();
        return true;
    }

    if (payload_len > 0) {
        uint8_t *dst = reinterpret_cast<uint8_t *>(ctx->placement.base_addr + msg_off);
        const uint8_t *src = rsp.pkt.payload.data();
        if (!dst || !src) {
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::READ_RESPONSE,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                              false);
            cleanup_rsp_handle();
            return true;
        }
        std::memcpy(dst, src, payload_len);
    }

    if (ctx->total_len > 0) {
        const uint32_t chunk_idx = msg_off / ctx->chunk_payload_size;
        const uint32_t inferred_base_psn = (meta.psn >= chunk_idx) ? (meta.psn - chunk_idx) : meta.psn;
        if (ctx->base_psn == 0 || inferred_base_psn < ctx->base_psn) {
            ctx->base_psn = inferred_base_psn;
        }
        if (chunk_idx >= ctx->expected_chunks) {
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::READ_RESPONSE,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR),
                              false);
            cleanup_rsp_handle();
            return true;
        }
        switch (markChunkArrived(*ctx, chunk_idx)) {
        case ChunkArrivalResult::ALREADY_ARRIVED:
            break;
        case ChunkArrivalResult::MARKED_OK:
            break;
        case ChunkArrivalResult::NO_BITMAP:
            completeRxMessage(key,
                              *ctx,
                              PDC_RX_completion_type::READ_RESPONSE,
                              static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                              false,
                              PDC_RX_completion_notify_kind::OP_COMPLETE,
                              0,
                              PDC_RX_failure_kind::PDS_NACK,
                              UET_NO_BITMAP);
            return true;
        }
    }

    if ((msg_off + payload_len) >= ctx->total_len) {
        ctx->saw_eom = true;
    }
    advanceMessageFrontier(*ctx);

    if ((ctx->total_len == 0 && ctx->saw_eom) ||
        (ctx->saw_eom && ctx->chunks_done == ctx->expected_chunks)) {
        completeRxMessage(key,
                          *ctx,
                          PDC_RX_completion_type::READ_RESPONSE,
                          static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                          true,
                          PDC_RX_completion_notify_kind::OP_COMPLETE,
                          ctx->total_len);
    }
    cleanup_rsp_handle();
    return true;
}

bool PDC::handleRudRxResponse(const PDStoNET_pkt *pkt)
{
    return directPlaceRudResponse(pkt);
}
