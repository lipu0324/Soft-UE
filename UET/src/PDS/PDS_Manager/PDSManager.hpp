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
 * @file             PDSManager.hpp
 * @brief            PDSManager.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * PDSManager.hpp
 */

#ifndef PDS_MANAGER_HPP
#define PDS_MANAGER_HPP

#include "../../Transport_Layer.hpp"
#include "../../logger/Logger.hpp"
#include "../PDC/process/IPDCProcessManager.hpp"
#include "../PDC/process/TPDCProcessManager.hpp"
#include "../PDC/process/ThreadSafeQueue.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <queue>
#include <unordered_map>
#include <vector>

struct RudResourceStats
{
    size_t arrival_blocks_in_use{0};
    size_t arrival_blocks_peak{0};
    size_t arrival_alloc_failures{0};
    size_t max_bitmap_blocks{0};
    size_t bitmap_blocks_in_use{0};
    size_t bitmap_blocks_available{0};
    size_t unexpected_msgs_in_use{0};
    size_t max_unexpected_msgs{0};
    size_t unexpected_msgs_peak{0};
    size_t unexpected_bytes_in_use{0};
    size_t max_unexpected_bytes{0};
    size_t unexpected_bytes_available{0};
    size_t unexpected_bytes_peak{0};
    size_t unexpected_alloc_failures{0};
};

enum class RudFailureBucket : uint8_t
{
    RC_NO_MATCH = 0,
    RC_PARTIAL_WRITE = 1,
    RC_PROTOCOL_ERROR = 2,
    RC_NO_BUFFER = 3,
    UET_NO_BITMAP = 4,
};

struct RudRuntimeStats
{
    size_t active_retry_states{0};
    size_t retry_scheduled{0};
    size_t retry_rc_no_match_scheduled{0};
    size_t retry_fired{0};
    size_t retry_giveups{0};
    size_t retry_rc_no_match_last_1s{0};
    size_t retry_terminalized_by_rto_exhaust{0};
    size_t retry_terminalized_by_close_reset{0};
    size_t retry_terminalized_by_teardown_orphan{0};
    size_t retry_state_orphan_cleanups{0};
    size_t retry_terminal_duplicates_ignored{0};
    size_t retry_terminalized_last_1s{0};
    size_t active_read_response_states{0};
    size_t read_response_terminalized_by_rto_exhaust{0};
    size_t read_response_terminalized_by_close_reset{0};
    size_t read_response_terminalized_by_teardown_orphan{0};
    size_t read_response_orphan_cleanups{0};
    size_t read_response_terminal_duplicates_ignored{0};
    size_t read_response_terminalized_last_1s{0};

    size_t ctrl_ack_req_sent{0};
    size_t ctrl_ack_req_suppressed{0};
    size_t ctrl_ack_req_last_1s{0};
    size_t ctrl_sack_sent{0};
    size_t ctrl_sack_suppressed{0};
    size_t ctrl_sack_last_1s{0};
    size_t ctrl_nack_sent{0};
    size_t ctrl_nack_suppressed{0};
    size_t ctrl_nack_last_1s{0};
    size_t ctrl_nack_fatal_sent{0};
    size_t ctrl_nack_resource_sent{0};
    size_t ctrl_nack_resource_last_1s{0};
    size_t ctrl_nack_resource_suppressed{0};
    size_t ctrl_nack_loss_sent{0};
    size_t ctrl_nack_loss_last_1s{0};
    size_t ctrl_nack_loss_suppressed{0};
    size_t ctrl_budget_deferred{0};
    size_t ctrl_budget_class_b_deferred{0};
    size_t ctrl_budget_class_c_deferred{0};
    size_t ctrl_gap_nack_sent{0};
    size_t ctrl_gap_nack_suppressed{0};
    size_t ack_ctrl_ext_sent{0};
    size_t ack_sack_piggyback_sent{0};
    size_t ack_credit_piggyback_sent{0};
    size_t ack_ackreq_hint_piggyback_sent{0};
    size_t ack_receiver_pressure_piggyback_sent{0};
    size_t ack_ctrl_ext_last_1s{0};
    size_t credit_cp_sent{0};
    size_t credit_refresh_sent{0};
    size_t credit_refresh_suppressed{0};
    size_t credit_refresh_last_1s{0};
    size_t credit_req_sent{0};
    size_t credit_req_last_1s{0};
    size_t credit_resync_req_sent{0};
    size_t credit_resync_rsp_sent{0};
    size_t credit_resync_success{0};
    size_t credit_resync_timeout{0};
    size_t credit_updates_rx{0};
    size_t credit_stale_ignored{0};
    size_t credit_gate_blocked{0};
    size_t credit_gate_blocked_last_1s{0};
    size_t piggyback_promoted{0};
    size_t standalone_fallback_sent{0};

    size_t unexpected_buffered_in_use{0};
    size_t unexpected_semantic_accepted_in_use{0};
    size_t unexpected_partial_in_use{0};
    size_t unexpected_match_count{0};
    size_t unexpected_partial_timeout_cleanups{0};
    size_t unexpected_close_reset_cleanups{0};
    uint64_t unexpected_max_buffered_residence_ms{0};

    size_t arrival_block_release_count{0};
    size_t duplicate_before_epsn_hits{0};

    size_t send_semantic_accept_success{0};
    size_t send_target_delivery_complete_success{0};
    size_t write_complete_success{0};
    size_t read_response_complete_success{0};

    size_t failure_rc_no_match{0};
    size_t failure_rc_partial_write{0};
    size_t failure_rc_protocol_error{0};
    size_t failure_rc_no_buffer{0};
    size_t failure_uet_no_bitmap{0};
};

class RudResourcePool
{
public:
    RudBitmapPoolHandle acquireArrivalBlock(uint32_t block_base);
    void releaseArrivalBlock(RudBitmapPoolHandle &handle);

    RudUnexpectedBufferHandle acquireUnexpectedBuffer(uint32_t bytes);
    void releaseUnexpectedBuffer(RudUnexpectedBufferHandle &handle);

    void configure(size_t max_bitmap_blocks, size_t max_unexpected_msgs, size_t max_unexpected_bytes);
    RudResourceStats stats() const;

private:
    mutable std::mutex mu_;
    std::vector<std::unique_ptr<RudBitmapBlock>> free_bitmap_blocks_;
    size_t max_bitmap_blocks_{1024};
    size_t bitmap_blocks_total_{0};
    size_t bitmap_blocks_in_use_{0};
    size_t bitmap_blocks_peak_{0};
    size_t arrival_alloc_failures_{0};
    size_t unexpected_msgs_in_use_{0};
    size_t unexpected_msgs_peak_{0};
    size_t unexpected_bytes_in_use_{0};
    size_t unexpected_bytes_peak_{0};
    size_t max_unexpected_msgs_{64};
    size_t max_unexpected_bytes_{1u << 20};
    size_t unexpected_alloc_failures_{0};
};

RudResourcePool &sharedRudResourcePool();
void configureSharedRudResourcePool(size_t max_bitmap_blocks, size_t max_unexpected_msgs, size_t max_unexpected_bytes);
RudResourceStats getSharedRudResourceStats();
RudRuntimeStats getRudRuntimeStats();
void resetRudRuntimeStats();
void setRudActiveRetryStates(size_t active_states);
void noteRudRetryScheduled();
void noteRudRcNoMatchRetryScheduled();
void noteRudRetryFired();
void noteRudRetryGiveup();
void noteRudRetryTerminalized(SenderTerminalReason reason);
void noteRudRetryStateOrphanCleanup();
void noteRudRetryTerminalDuplicateIgnored();
void setRudActiveReadResponseStates(size_t active_states);
void noteRudReadResponseTerminalized(ReadResponseTerminalReason reason);
void noteRudReadResponseOrphanCleanup();
void noteRudReadResponseTerminalDuplicateIgnored();
void noteRudCtrlAckReqSent();
void noteRudCtrlAckReqSuppressed();
void noteRudCtrlSackSent();
void noteRudCtrlSackSuppressed();
void noteRudCtrlNackSent();
void noteRudCtrlNackSuppressed();
void noteRudCtrlBudgetDeferred();
void noteRudCtrlBudgetDeferredByClass(bool class_b);
void noteRudCtrlGapNackSent();
void noteRudCtrlGapNackSuppressed();
void noteRudCtrlNackSentByClass(uint8_t nack_class);
void noteRudCtrlNackSuppressedByClass(uint8_t nack_class);
void noteRudAckCtrlExtSent(bool sack_present,
                           bool credit_present,
                           bool ackreq_hint_present,
                           bool receiver_pressure_present);
void noteRudCreditCpSent();
void noteRudCreditRefreshSent();
void noteRudCreditRefreshSuppressed();
void noteRudCreditReqSent();
void noteRudCreditResyncReqSent();
void noteRudCreditResyncRspSent();
void noteRudCreditResyncSuccess();
void noteRudCreditResyncTimeout();
void noteRudCreditUpdateRx();
void noteRudCreditStaleIgnored();
void noteRudCreditGateBlocked();
void noteRudPiggybackPromoted();
void noteRudStandaloneFallbackSent();
void noteRudUnexpectedAllocated();
void noteRudUnexpectedSemanticAccepted();
void noteRudUnexpectedMatched();
void noteRudUnexpectedReleased(bool semantic_accepted, bool due_close_reset, uint64_t residence_ms);
void noteRudUnexpectedPartialTimeoutCleanup();
void noteRudArrivalBlockReleased(size_t count = 1);
void noteRudDuplicateBeforeEpsn();
void noteRudCompletionSuccess(PDC_RX_completion_type type, PDC_RX_completion_notify_kind notify_kind);
void noteRudFailureBucket(RudFailureBucket bucket);

class PDS_Manager
{
public:
    enum class AllocPDCResult : uint8_t
    {
        CREATED = 0,
        ALREADY_OPEN,
        CREATE_FAILED,
    };

    TPDCProcessManager TPDC_Processmanager;
    IPDCProcessManager IPDC_Processmanager;
    // Protects local std::queue members (SES_tx_req_q / SES_tx_rsp_q / Net_rx_pkt_q / etc.)
    // that are pushed from other threads and popped by the PDS main loop.
    mutable std::mutex local_queue_mutex_;
    pdc pdc_list[MAX_PDC * 2];
    std::queue<SES_PDS_req> SES_tx_req_q;
    std::queue<SES_PDS_rsp> SES_tx_rsp_q;
    std::queue<PDStoNET_pkt> Net_rx_pkt_q;

    std::queue<SES_PDS_eager> SES_eager_req_q;
    std::queue<PDS_SES_error> PDS_error_q;

    ThreadSafeQueue<PDStoNET_pkt> PDStoNet;
    ThreadSafeQueue<PDC_SES_req> PDCtoSES_req;
    ThreadSafeQueue<PDC_SES_rsp> PDCtoSES_rsp;
    ThreadSafeQueue<uint16_t> PDC_close_q;
    int open_cnt = 0;
    int pend_cnt = 0;
    int closing_cnt = 0;
    bool pause_ses = false;
    int event_cnt = 0;
    int8_t pdc_qdepth[NUM_BANKS][PDCs_PER_BANK] = {0};
    uint8_t BitMap[MAX_PDC] = {0};
    std::map<uint16_t, uint16_t> msg_map;
    std::queue<pend_node> pend_q;

    bool initPDSM();
    void mainChk();
    void sesTxRsp();
    void rxPkt();
    bool checkRxPkt(PDStoNET_pkt *rx);
    void unexpectedOrRxOOR(PDStoNET_pkt *rx);
    void sendNack(PDStoNET_pkt *rx, PDS_Nack_Codes nack_type);
    void SESTxReq();
    AllocPDCResult allocPDC(uint16_t pdc_id, uint32_t dst_fep, uint32_t src_fep, uint8_t delivery_mode);
    bool isOOR();
    bool PDCOpen(int pdc_id);
    void txOORPendEnqueue(SES_PDS_req *tx);
    bool pendQFull();
    pend_node createPendNode(SES_PDS_req tx);
    void fwdPkt2PDC(struct SES_PDS_req *pkt, int pdc_id);
    void fwdPkt2PDC(struct SES_PDS_rsp *pkt, int pdc_id);
    void fwdPkt2PDC(struct PDStoNET_pkt *pkt, int pdc_id);
    void resourceCheck();
    void pendTimeOut(pend_node node);
    void sendError2SES();
    void dropPkt(pend_node node);
    bool isPendNodeOverTime(pend_node node);
    bool assignPDC(uint16_t msgid, uint16_t pdc_id);
    bool assignPDC(uint32_t job_id,
                   uint32_t dest_fa,
                   uint8_t trafficclass,
                   uint8_t deliverymode,
                   uint16_t msgid,
                   uint16_t *pdc_id);
    int muxTx2PDCID(uint32_t job_id, uint32_t dest_fa, uint8_t trafficclass, uint8_t deliverymode);
    int muxRx2PDCID(uint32_t src_addr, uint32_t dest_addr, uint16_t spdcid);
    int selectPDC2Close();
    int requestCloseAllOpenIPDCs();
    bool PDCClose();

private:
    struct RxBindingKey
    {
        uint32_t src_fep{0};
        uint32_t dst_fep{0};
        uint16_t remote_spdcid{0};
        uint8_t delivery_mode{0};

        bool operator==(const RxBindingKey &other) const
        {
            return src_fep == other.src_fep &&
                   dst_fep == other.dst_fep &&
                   remote_spdcid == other.remote_spdcid &&
                   delivery_mode == other.delivery_mode;
        }
    };

    struct RxBindingKeyHash
    {
        size_t operator()(const RxBindingKey &key) const
        {
            const size_t a = static_cast<size_t>(key.src_fep);
            const size_t b = static_cast<size_t>(key.dst_fep);
            const size_t c = static_cast<size_t>(key.remote_spdcid);
            const size_t d = static_cast<size_t>(key.delivery_mode);
            return (((a * 1315423911u) ^ (b << 1)) * 2654435761u) ^ (c << 7) ^ d;
        }
    };

    enum PDC_TYPE
    {
        IPDC = 0,
        TPDC = 1,
    };

    mutable std::mutex rx_binding_mu_;
    std::unordered_map<RxBindingKey, uint16_t, RxBindingKeyHash> rx_binding_map_;

    PDS_Nack_Codes checkUnexpectEvent(PDStoNET_pkt *rx);
    PDC_TYPE getPDCType(int pdc_id);
    bool pdsError();
    bool findRxBinding(const RxBindingKey &key, uint16_t *pdc_id) const;
    bool isSameBinding(uint16_t pdc_id, const RxBindingKey &key) const;
    void bindPdc(uint16_t pdc_id,
                 uint32_t src_fep,
                 uint32_t dst_fep,
                 uint16_t remote_spdcid,
                 uint8_t delivery_mode);
    void clearPdcBinding(uint16_t pdc_id);
    void bindRxConnection(const RxBindingKey &key, uint16_t pdc_id);
    void clearRxBindingsForPdc(uint16_t pdc_id);
    int findFallbackRxPdc(uint16_t preferred_pdcid) const;
};

#endif
