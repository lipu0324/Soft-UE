#include "PDC_RudInternals.hpp"

RudBitmapBlock *PDC::findHotArrivalBlock(RxMessageContext &ctx, uint32_t block_base)
{
    for (size_t i = 0; i < kRudHotBlockCount; ++i) {
        if (ctx.hot_block_ptrs[i] && ctx.hot_block_bases[i] == block_base) {
            return ctx.hot_block_ptrs[i];
        }
    }
    return nullptr;
}

RudBitmapBlock *PDC::getArrivalBlock(RxMessageContext &ctx, uint32_t block_base, bool create_if_missing)
{
    if (RudBitmapBlock *hot = findHotArrivalBlock(ctx, block_base)) {
        return hot;
    }

    auto it = ctx.blocks.find(block_base);
    if (it == ctx.blocks.end()) {
        if (!create_if_missing) {
            return nullptr;
        }
        it = ctx.blocks.emplace(block_base, sharedRudResourcePool().acquireArrivalBlock(block_base)).first;
    }

    RudBitmapBlock *block = it->second.block.get();
    for (size_t i = kRudHotBlockCount; i > 1; --i) {
        ctx.hot_block_bases[i - 1] = ctx.hot_block_bases[i - 2];
        ctx.hot_block_ptrs[i - 1] = ctx.hot_block_ptrs[i - 2];
    }
    ctx.hot_block_bases[0] = block_base;
    ctx.hot_block_ptrs[0] = block;
    return block;
}

PDC::ChunkArrivalResult PDC::markChunkArrived(RxMessageContext &ctx, uint32_t chunk_idx)
{
    if (chunk_idx < ctx.ePSN) {
        noteRudDuplicateBeforeEpsn();
        return ChunkArrivalResult::ALREADY_ARRIVED;
    }
    const uint32_t block_base = (chunk_idx / kRudArrivalBlockSize) * kRudArrivalBlockSize;
    const uint32_t bit_index = chunk_idx - block_base;
    const uint64_t bit = (1ULL << bit_index);
    auto existing = ctx.blocks.find(block_base);
    if (existing != ctx.blocks.end() && existing->second.block &&
        (existing->second.block->received_bits & bit) != 0) {
        return ChunkArrivalResult::ALREADY_ARRIVED;
    }

    RudBitmapBlock *block = getArrivalBlock(ctx, block_base, true);
    if (!block) {
        return ChunkArrivalResult::NO_BITMAP;
    }

    if ((block->received_bits & bit) != 0) {
        return ChunkArrivalResult::ALREADY_ARRIVED;
    }

    block->received_bits |= bit;
    if (block->received_count < kRudArrivalBlockSize) {
        ++block->received_count;
    }
    block->full = (block->received_count == kRudArrivalBlockSize);
    ++ctx.chunks_done;
    return ChunkArrivalResult::MARKED_OK;
}

bool PDC::isChunkArrived(const RxMessageContext &ctx, uint32_t chunk_idx) const
{
    if (chunk_idx < ctx.ePSN) {
        return true;
    }
    const uint32_t block_base = (chunk_idx / kRudArrivalBlockSize) * kRudArrivalBlockSize;
    auto it = ctx.blocks.find(block_base);
    if (it == ctx.blocks.end() || !it->second.block) {
        return false;
    }
    const uint32_t bit_index = chunk_idx - block_base;
    return (it->second.block->received_bits & (1ULL << bit_index)) != 0;
}

void PDC::advanceMessageFrontier(RxMessageContext &ctx)
{
    while (ctx.ePSN < ctx.expected_chunks) {
        const uint32_t chunk_idx = ctx.ePSN;
        const uint32_t block_base = (chunk_idx / kRudArrivalBlockSize) * kRudArrivalBlockSize;
        auto it = ctx.blocks.find(block_base);
        if (it == ctx.blocks.end() || !it->second.block) {
            break;
        }

        RudBitmapBlock *block = it->second.block.get();
        if (block->full && chunk_idx == block_base) {
            ctx.ePSN = std::min(ctx.expected_chunks, block_base + kRudArrivalBlockSize);
            continue;
        }

        const uint32_t bit_index = chunk_idx - block_base;
        if ((block->received_bits & (1ULL << bit_index)) == 0) {
            break;
        }
        ++ctx.ePSN;
    }
    pruneCompletedArrivalBlocks(ctx);
}

void PDC::pruneCompletedArrivalBlocks(RxMessageContext &ctx)
{
    const uint32_t releasable_before = (ctx.ePSN / kRudArrivalBlockSize) * kRudArrivalBlockSize;
    if (releasable_before == 0) {
        return;
    }

    for (auto it = ctx.blocks.begin(); it != ctx.blocks.end();) {
        if ((it->first + kRudArrivalBlockSize) <= ctx.ePSN) {
            const uint32_t released_base = it->first;
            sharedRudResourcePool().releaseArrivalBlock(it->second);
            noteRudArrivalBlockReleased();
            it = ctx.blocks.erase(it);
            for (size_t i = 0; i < kRudHotBlockCount; ++i) {
                if (ctx.hot_block_bases[i] == released_base) {
                    ctx.hot_block_bases[i] = 0;
                    ctx.hot_block_ptrs[i] = nullptr;
                }
            }
        } else {
            ++it;
        }
    }
}
