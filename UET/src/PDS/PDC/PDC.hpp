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
 * @file             PDC.hpp
 * @brief            PDC.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This header defines the base PDC class and related structures for reliable data delivery.
 */

#ifndef PDC_HPP
#define PDC_HPP

//#include "../SES/SES.hpp"
// Update the path below to the correct relative or absolute path where PDS.hpp exists
#include "../PDS.hpp"
#include "../../logger/Logger.hpp"
#include "process/ThreadSafeQueue.hpp"
#include "RTOTimer/RTOTimer.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <queue>
#include <map>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <functional>
#include <memory>
#include <array>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <vector>

// Retransmission configuration
#define USE_RTO 1

/** Maximum PSN range, used to limit the valid range of sequence numbers */ 
//#define Max_PSN_Range 500

/**
 * @enum pdc_mode
 * @brief  PDC operation mode types
 * @details Defines the different modes of operation for PDC, including reliable unidirectional delivery, reliable ordered delivery, reliable unidirectional delivery - immediate, and unreliable unidirectional delivery  
 */
enum pdc_mode
{
    RUD,   /**<  (Reliable Unidirectional Delivery) */
    ROD,   /**<  (Reliable Ordered Delivery) */
    RUDI,  /**< - (Reliable Unidirectional Delivery - Immediate) */
    UUD    /**<  (Unreliable Unidirectional Delivery) */
};

/**
 * @enum pdc_state
 * @brief PDC connection state enumeration
 */
enum pdc_state
{
    CLOSED,         /**< Closed connection state */
    CREATING,       /**< Creating connection state */
    ESTABLISHED,    /**< Established connection state */
    QUIESCE,        /**< Quiet connection state, ready to close */
    ACK_WAIT,       /**< Awaiting confirmation state */
    CLOSE_ACK_WAIT, /**< Awaiting close confirmation state */
    PENDING         /**< Pending state */
};

/**
 * @enum cm_type
 * @brief Control message type enumeration Control message type enumeration 
 * Defines the different control message types supported by PDC, used for control information exchange between PDCs  
 * Defines various control message types supported by PDC for control information exchange between PDCs
 */
enum cm_type {
    NOOP,        /**< No-operation control message */
    ACK_REQ,     /**< Acknowledgment request control message */
    CLR_CMD,     /**< Clear command control message */
    CLR_REQ,     /**< Clear request control message */
    CLOSE_CMD,   /**< Close command control message */
    CLOSE_REQ,   /**< Close request control message */
    PROBE,       /**< Probe control message, used to detect connection state */
    CREDIT,      /**< Flow control credit control message */
    CREDIT_REQ,  /**< Flow control credit request control message */
    SACK_CTRL,   /**< Selective acknowledgment control message for RUD */
    NEGOTIATION, /**< Negotiation control message, used for parameter negotiation */
    NONE         /**< No control message */
};

/**
 * @enum error_type
 * @brief PDC error type enumeration
 */
enum error_type
{
    OPEN,       /**< Error during connection open */
    ACK_ERROR,  /**< Acknowledgment packet error */
    OOO,        /**< Packet out of order error (Out Of Order) */
    OOO_ACCEPT, /**< RUD accepts the packet into the out-of-order window */
    DROP,       /**< Packet drop error */
    INV_SYN,    /**< Invalid SYN flag */
    INV_DPDCID  /**< Invalid target PDCID */
};

enum class NackCtrlClass : uint8_t
{
    FATAL_PROTOCOL = 0,
    RESOURCE_RECOVERABLE = 1,
    LOSS_INFERENCE = 2,
};

enum class CreditControlReason : uint8_t
{
    NONE = 0,
    REFRESH = 1,
    RESYNC_RESPONSE = 2,
};

#include "PDCStringUtils.hpp"


// Convenient macro definitions for directly outputting enum strings in logs 
#define STATE_STR(state) pdcStateToString(state).c_str()
#define MODE_STR(mode) pdcModeToString(mode).c_str()
#define CM_TYPE_STR(type) cmTypeToString(type).c_str()
#define ERROR_TYPE_STR(type) errorTypeToString(type).c_str()
#define PDS_TYPE_STR(type) pdsTypeToString(type).c_str()
#define PDS_HDR_TYPE_STR(type) pdsHeaderTypeToString(type).c_str()
#define PDS_NEXT_HDR_STR(type) pdsNextHdrToString(type).c_str()
#define PDS_CTL_TYPE_STR(type) pdsCtlTypeToString(type).c_str()
#define NACK_CODE_STR(code) nackCodeToString(code).c_str()

// Forward declarations for PDC related structures
struct PDC_SES_req;
struct PDC_SES_rsp;
struct PDS_PDC_req;
struct SES_PDC_rsp;
struct TX_pkt_meta;
struct RX_pkt_meta;

/**
 * @struct TX_pkt_meta
 * @brief Metadata structure for sending packets Metadata structure for sending packets Metadata structure for sending packets 
 *
 * Stores various management information for sending packets, used for retransmission and timeout processing
 */
struct TX_pkt_meta
{
    uint16_t tx_pkt_handle; /**< Sending packet handle */
    uint16_t rto;           /**< Retransmission timeout time */
    uint16_t retry_cnt;     /**< Retry count */
    uint64_t job_id{0};
    uint16_t msg_id{0};
    uint32_t dst_fep{0};
    bool is_retry{false};
    bool is_request_som{false};
    bool is_send_som{false};
    bool is_read_response_data{false};
    uint32_t message_offset{0};
    bool is_last_fragment{false};
    bool terminal_emitted{false};
};

struct SenderTerminalKey
{
    uint64_t job_id{0};
    uint16_t msg_id{0};
    uint32_t dst_fep{0};

    bool operator==(const SenderTerminalKey &other) const noexcept
    {
        return job_id == other.job_id && msg_id == other.msg_id && dst_fep == other.dst_fep;
    }
};

struct ReadResponseTerminalKey
{
    uint64_t job_id{0};
    uint16_t msg_id{0};
    uint32_t dst_fep{0};

    bool operator==(const ReadResponseTerminalKey &other) const noexcept
    {
        return job_id == other.job_id && msg_id == other.msg_id && dst_fep == other.dst_fep;
    }
};

struct ReadResponseTerminalKeyHash
{
    size_t operator()(const ReadResponseTerminalKey &key) const noexcept
    {
        const size_t a = std::hash<uint64_t>{}(key.job_id);
        const size_t b = std::hash<uint16_t>{}(key.msg_id);
        const size_t c = std::hash<uint32_t>{}(key.dst_fep);
        return a ^ (b << 1) ^ (c << 2);
    }
};

struct SenderTerminalKeyHash
{
    size_t operator()(const SenderTerminalKey &key) const noexcept
    {
        const size_t a = std::hash<uint64_t>{}(key.job_id);
        const size_t b = std::hash<uint16_t>{}(key.msg_id);
        const size_t c = std::hash<uint32_t>{}(key.dst_fep);
        return a ^ (b << 1) ^ (c << 2);
    }
};

/**
 * @struct RX_pkt_meta
 * @brief Metadata structure for receiving packets Metadata structure for receiving packets Metadata structure for receiving packets 
 *
 * Stores various management information for received packets, used for packet processing and state tracking  
 */
struct RX_pkt_meta
{
    PDS_type type;          /**< Packet type (Request/ACK/CP/NACK) */
    PDS_next_hdr next_hdr;  /**< SES header type */
    uint16_t spdcid;        /**< Receiver PDCID */
    uint32_t src_fep;       /**< Source FEP identifier */
    uint32_t psn;           /**< Packet sequence number (PSN) */
    uint32_t clear_psn;     /**< Clear PSN, used for flow control */
    uint8_t syn : 1;        /**< SYN flag (establish connection) */
    uint8_t retx : 1;       /**< Retransmission flag */
    uint8_t ar : 1;         /**< ACK request flag */
    bool som;               /**< Message start flag (Start Of Message) */
    uint16_t payload_len;   /**< Payload length */
};

struct RxMessageKey
{
    uint8_t opcode{0};
    uint64_t job_id{0};
    uint16_t msg_id{0};
    uint32_t src_fep{0};
    uint16_t pdcid{0};

    bool operator==(const RxMessageKey &other) const noexcept
    {
        return opcode == other.opcode && job_id == other.job_id && msg_id == other.msg_id &&
               src_fep == other.src_fep && pdcid == other.pdcid;
    }
};

struct RxMessageKeyHash
{
    size_t operator()(const RxMessageKey &key) const noexcept
    {
        const size_t a = static_cast<size_t>(key.opcode);
        const size_t b = static_cast<size_t>(key.job_id);
        const size_t c = static_cast<size_t>(key.msg_id);
        const size_t d = static_cast<size_t>(key.src_fep);
        const size_t e = static_cast<size_t>(key.pdcid);
        return (a << 56) ^ (b << 24) ^ (c << 8) ^ (d << 3) ^ e;
    }
};

struct UnexpectedSendContext
{
    RudUnexpectedBufferHandle buffer;
    int64_t created_at_ms{0};
    int64_t last_activity_ms{0};
    bool semantic_accepted{false};
    bool buffered_complete{false};
    bool matched_to_recv{false};
};

struct RxMessageContext
{
    uint32_t ePSN{0};
    uint32_t base_psn{0};
    uint32_t total_len{0};
    uint32_t chunk_payload_size{0};
    uint32_t expected_chunks{0};
    uint32_t chunks_done{0};
    bool saw_eom{false};
    RxPlacementDescriptor placement{};
    std::unordered_map<uint32_t, RudBitmapPoolHandle> blocks;
    std::array<uint32_t, 4> hot_block_bases{{0, 0, 0, 0}};
    std::array<RudBitmapBlock *, 4> hot_block_ptrs{{nullptr, nullptr, nullptr, nullptr}};
    RudSendPlacementMode send_mode{RudSendPlacementMode::DIRECT_RECV};
    std::unique_ptr<UnexpectedSendContext> unexpected;
    bool completed{false};
    bool failed{false};
    uint16_t rx_pkt_handle{0};
};

struct SendCompletionTombstone
{
    uint32_t modified_length{0};
    int64_t completed_at_ms{0};
};

struct ReceiverFlowCreditSnapshot
{
    uint32_t job_id{0};
    uint16_t credit_gen{0};
    uint16_t posted_recv_credits{0};
    uint16_t unexpected_msg_credits{0};
    uint16_t unexpected_byte_credits{0};
    uint8_t byte_credit_shift{12};
    uint8_t flags{0};
};

struct LocalReceiverCreditState
{
    ReceiverFlowCreditSnapshot snapshot{};
    bool dirty{true};
    int64_t last_dirty_ms{0};
    int64_t last_sent_ms{0};
};

struct PeerReceiverCreditState
{
    bool valid{false};
    uint16_t credit_gen_seen{0};
    uint16_t posted_recv_credits{0};
    uint16_t unexpected_msg_credits{0};
    uint16_t unexpected_byte_credits{0};
    bool bootstrap_used{false};
    int64_t blocked_since_ms{0};
    int64_t last_credit_req_ms{0};
};

/**
 * @class PDC
 * @brief PDC base class, containing common logic and data structures for I_PDC and T_PDC
 *
 * 
 * 
 * I_PDC and T_PDC will inherit from this base class and implement their specific functionality.
 */
	class PDC
	{
	public:
        using ResolveRxRequestPlacementFn = std::function<RxPlacementDescriptor(const PDC_SES_req &)>;
        using ResolveRxResponsePlacementFn = std::function<RxPlacementDescriptor(const PDC_SES_rsp &)>;
        using CompleteRxOperationFn = std::function<void(const PDC_RX_completion &)>;
        using CompleteRequestTerminalFn = std::function<void(const RequestTerminalCompletion &)>;
        using CompleteSenderTerminalFn = std::function<void(const SenderTerminalCompletion &)>;
        using CompleteReadResponseTerminalFn = std::function<void(const ReadResponseTerminalCompletion &)>;
        using ResolvePostedRecvCreditsFn = std::function<uint16_t(uint64_t, uint16_t, uint32_t)>;

	    // Queues and mapping tables
	    std::map<uint32_t, TX_pkt_meta> tx_pkt_map;       /**< Store metadata of sent packets */
	    std::map<uint16_t, RX_pkt_meta> rx_pkt_map;       /**< Store metadata of received packets */
	    std::map<uint32_t, PDStoNET_pkt> tx_pkt_buffer;   /**< Store unacknowledged request packets */
	    std::map<uint32_t, PDStoNET_pkt> tx_ack_buffer;   /**< Store guaranteed delivery ACK packets */
	    const unsigned int tx_ack_buffer_capa = 10;                /**< ACK buffer capacity */

	    // Protects all std::queue members below.
	    // These queues are accessed by multiple threads (PDC threads, process managers, provider threads).
	    mutable std::mutex queue_mutex_;

	    RTOTimer rto_timer_;    /**< Retransmission timer Retransmission timer*/


 // ==================== Common Member Variables ====================
    pdc_mode mode;          /**< PDC operation mode / PDC operation mode */
    uint16_t SPDCID;        /**< Source PDC identifier / Source PDC identifier */
    uint16_t DPDCID;        /**< Destination PDC identifier / Destination PDC identifier */
    int unack_cnt;          /**< Unacknowledged packet count / Unacknowledged packet count */
    bool allACK;           /**< Full acknowledgment flag / Full acknowledgment flag */
    int open_msg;          /**< Open message count / Open message count */
    bool SYN;              /**< Synchronization flag / Synchronization flag */
    int MPR;               /**< Maximum Packet Rate / Maximum packet rate */
    int ACK_GEN_COUNT;     /**< ACK generation counter (determines when to send ACK) / Used for cumulative ACK to determine if ACK packet needs to be sent */

    std::atomic<int> pending_ops{0};        /**< In-flight message count / 未完成消息计数 */
    std::atomic<int64_t> last_activity_ms{0}; /**< Last activity timestamp (ms) / 最近活动时间戳 */
    static constexpr int64_t kIdleCloseMs = 2000; /**< Idle window before close / 允许关闭的空闲窗口 */

    uint32_t start_psn;     /**< Initial packet sequence number / Initial packet sequence number */
    uint32_t tx_cur_psn;    /**< Current transmission sequence number / Current transmission sequence number */
    uint32_t clear_psn;     /**< Clear sequence number / Clear sequence number */
    uint32_t rx_cur_psn;    /**< Current receive sequence number / Current receive sequence number */
    uint32_t cack_psn;      /**< Cumulative ACK sequence number / Cumulative ACK sequence number */
    uint32_t rx_clear_psn;  /**< Recorded TX clear sequence number */

    bool pause_pdc;        /**< PDC transmission pause flag / PDC transmission pause flag */
    cm_type gen_cm;        /**< Pending control message type / Pending control message type */
    bool gen_ack;          /**< ACK generation flag / ACK generation flag */

    bool trim;             /**< Trimming flag / Trimming flag */
    bool rx_error;         /**< Receive error flag / Receive error flag */
    error_type error_chk;  /**< Error check type / Error check type */

    bool close_error;      /**< Close error flag / Close error flag */
    bool closing;          /**< Closing in progress flag / Closing in progress flag */
    int pdc_close_timer;    /**< PDC close timer / PDC close timer */

    uint32_t dst_fep;       /**< Destination IP address / Destination IP address */
    uint32_t src_fep;       /**< Source IP address / Source IP address */

    pdc_state state;       /**< Current PDC state / Current PDC state */
    std::queue<PDStoNET_pkt> tx_pkt_q;        /**< Transmission packet queue / Transmission packet queue */
    std::queue<PDC_SES_req> rx_req_pkt_q;     /**< Received request packet queue / Received request packet queue */
    std::queue<PDC_SES_rsp> rx_rsp_pkt_q;     /**< Response packet queue to SES layer / Response packet queue to SES layer */
	    std::queue<PDS_PDC_req> tx_req_q;         /**< PDS request transmission queue / PDS request transmission queue */
	    std::queue<SES_PDC_rsp> tx_rsp_q;         /**< SES response transmission queue / SES response transmission queue */
	    std::queue<PDStoNET_pkt> rx_pkt_q;        /**< Received packet queue from PDS / Received packet queue from PDS */
	    std::queue<uint32_t> rto_pkt_q;           /**< Retransmission timeout packet queue / Retransmission timeout packet queue */

        // RUD tracking state.
        std::set<uint32_t> rud_rx_ooo_psns;
        std::set<uint32_t> rud_tx_sacked_psns;
        std::unordered_map<RxMessageKey, RxMessageContext, RxMessageKeyHash> rud_rx_messages_;
        std::unordered_map<RxMessageKey, SendCompletionTombstone, RxMessageKeyHash> rud_completed_send_tombstones_;
        bool rud_sack_pending{false};
        bool rud_gap_pending{false};
        uint32_t rud_gap_psn{0};
        int64_t rud_sack_first_ms{0};
        int64_t rud_gap_first_ms{0};
        static constexpr int64_t kRudSackDelayMs = 5;
        static constexpr int64_t kRudAckReqMinIntervalMs = 2;
        static constexpr int64_t kRudGapDelayMs = 15;
        static constexpr int64_t kRudGapMaxIntervalMs = 120;
        static constexpr int64_t kRudCtrlBudgetWindowMs = 100;
        static constexpr int64_t kCreditPushDelayMs = 10;
        static constexpr int64_t kRecoverableNackMinIntervalMs = 5;
        static constexpr uint8_t kUnexpectedCreditByteShift = 12;
        static constexpr uint32_t kUnexpectedCreditUnitBytes = 1u << kUnexpectedCreditByteShift;
        static constexpr int kRudCtrlBudgetCapacity = 12;
        static constexpr int kRudCtrlBudgetClassBCost = 2;
        static constexpr int kRudCtrlBudgetClassCCost = 1;
        static constexpr uint16_t kAckCtrlExtSectionSack = ACK_CTRL_SECTION_SACK;
        static constexpr uint16_t kAckCtrlExtSectionCredit = ACK_CTRL_SECTION_CREDIT;
        static constexpr uint16_t kAckCtrlExtSectionAckReqHint = ACK_CTRL_SECTION_ACKREQ_HINT;
        static constexpr uint16_t kAckCtrlExtSectionReceiverPressure = ACK_CTRL_SECTION_RECEIVER_PRESSURE;
        static constexpr uint16_t kBootstrapSendCredits = 1;
        uint32_t last_ack_req_psn_{0};
        int64_t last_ack_req_ms_{0};
        uint32_t last_sack_base_psn_{0};
        uint32_t last_sack_bitmap_{0};
        int64_t last_sack_ms_{0};
        int64_t rud_gap_last_nack_ms_{0};
        int64_t rud_gap_retry_interval_ms_{kRudGapDelayMs};
        bool rud_gap_suppressed_in_window_{false};
        uint32_t rud_rsp_gap_psn_{0};
        int64_t rud_rsp_gap_first_ms_{0};
        int64_t rud_rsp_gap_last_nack_ms_{0};
        int64_t rud_rsp_gap_retry_interval_ms_{kRudGapDelayMs};
        bool rud_rsp_gap_suppressed_in_window_{false};
        int rud_ctrl_budget_tokens_{kRudCtrlBudgetCapacity};
        int64_t rud_ctrl_budget_last_refill_ms_{0};
        bool ctrl_tx_deferred_{false};
        bool skip_ctrl_emit_once_{false};
        std::unordered_map<uint32_t, LocalReceiverCreditState> local_receiver_credits_;
        std::unordered_map<uint32_t, PeerReceiverCreditState> peer_receiver_credits_;
        std::unordered_set<uint32_t> observed_receiver_jobs_;
        uint32_t pending_credit_job_id_{0};
        uint32_t pending_credit_req_job_id_{0};
        uint32_t last_credit_ack_job_id_{0};
        uint16_t local_credit_gen_{0};
        uint16_t local_credit_last_sent_gen_{0};
        uint16_t peer_credit_gen_seen_{0};
        uint16_t peer_credit_available_{0};
        bool peer_credit_valid_{false};
        bool local_credit_dirty_{true};
        bool bootstrap_credit_used_{false};
        uint16_t last_advertised_credit_{0};
        int64_t local_credit_dirty_since_ms_{0};
        int64_t last_credit_sent_ms_{0};
        int64_t credit_blocked_since_ms_{0};
        int64_t last_credit_req_ms_{0};
        uint16_t last_receiver_pressure_unexpected_byte_credits_{0};
        uint16_t last_receiver_pressure_bitmap_blocks_available_{0};
        uint16_t last_receiver_pressure_arrival_blocks_available_{0};
        uint16_t last_unexpected_msgs_in_use_{0};
        uint16_t last_pressure_sent_unexpected_msgs_in_use_{0};
        bool receiver_pressure_dirty_{true};
        CreditControlReason pending_credit_reason_{CreditControlReason::NONE};
        PDS_Nack_Codes last_resource_nack_code_{UET_TRIMMED};
        uint32_t last_resource_nack_psn_{0};
        uint32_t last_resource_nack_payload_{0};
        int64_t last_resource_nack_ms_{0};
        std::unordered_set<SenderTerminalKey, SenderTerminalKeyHash> sender_terminalized_keys_;
        std::unordered_set<SenderTerminalKey, SenderTerminalKeyHash> request_terminalized_keys_;
        std::unordered_set<ReadResponseTerminalKey, ReadResponseTerminalKeyHash> read_response_terminalized_keys_;

    // Public queue pointers  
    ThreadSafeQueue<PDStoNET_pkt>* public_net_queue = nullptr;
    ThreadSafeQueue<PDC_SES_req>* public_ses_req_queue = nullptr;
    ThreadSafeQueue<PDC_SES_rsp>* public_ses_rsp_queue = nullptr;
    ThreadSafeQueue<uint16_t>* public_close_queue = nullptr;

    // ==================== Constructors and Destructors ====================
    PDC();
    virtual ~PDC();
    static void setRxCallbacks(ResolveRxRequestPlacementFn req_cb,
                               ResolveRxResponsePlacementFn rsp_cb,
                               CompleteRxOperationFn complete_cb,
                               CompleteRequestTerminalFn request_terminal_cb,
                               CompleteSenderTerminalFn terminal_cb,
                               CompleteReadResponseTerminalFn read_terminal_cb,
                               ResolvePostedRecvCreditsFn posted_recv_cb);
    static bool matchUnexpectedSend(uint64_t job_id,
                                    uint16_t pdc_id,
                                    uint32_t src_fep,
                                    uint64_t completion_key,
                                    uint64_t base_addr,
                                    uint32_t buffer_len);
    static RequestTxProbe queryRequestTxProbe(uint64_t job_id,
                                              uint16_t msg_id,
                                              uint32_t dst_fep);
    static UnexpectedSendProbe queryUnexpectedSendProbe(uint64_t job_id,
                                                        uint16_t msg_id,
                                                        uint32_t src_fep);

    // ==================== Common Utility Functions ====================
    /**
     * @brief Format log message with PDCID information Format log message with PDCID information
     * @param message Original log message Original log message
     * @return Formatted message containing PDCID info Formatted message containing PDCID info
     */
    std::string formatLogMessage(const std::string &message) const
    {
        std::stringstream ss;
        ss << "[PDCID:" << SPDCID << "] " << message;
        return ss.str();
    }

    /**
     * @brief Get current timestamp Get current timestamp Get current timestamp
     * @return Formatted timestamp string Formatted timestamp string
     */
    static std::string getCurrentTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_time_t), "%H:%M:%S")
           << '.' << std::setfill('0') << std::setw(3) << now_ms.count() << " ";
        return ss.str();
    }

    /**
     * @brief Set receive handle Set receive handle Set receive handle
     * @param psn Packet sequence number Packet sequence number
     * @param spdcid Source PDC ID Source PDC ID
     * @return Generated receive handle Generated receive handle
     */
    uint16_t setRXhandle(uint32_t psn, uint16_t spdcid)
    {
        return (psn & 0xFFFF) | ((spdcid & 0xFF) << 16);
    }
    /**
     * @brief Get current PSN value Get current PSN value Get current PSN value
     * @return Current packet sequence number
     */
    uint32_t setPsn(){
        return tx_cur_psn;
    }
    /**
     * @brief Get receive PSN Get receive PSN Get receive PSN
     * @param psn Packet sequence number Packet sequence number
     * @param psn_off PSN offset  PSN offset
     * @return Calculated receive PSN Calculated receive PSN
     */
    uint32_t getRxpsn(uint32_t psn, uint32_t psn_off)
    {
        return psn + psn_off;
    }

    /**
     * @brief Check if NACK code is for closing Check if NACK code is for closing Check if NACK code is for closing type
     * @param nack_code NACK error code NACK error code
     * @return Whether it is for closing type Whether it is for closing type
     */
    static bool isClose(PDS_Nack_Codes nack_code)
    {
        return (nack_code == UET_NO_PDC_AVAIL || 
                nack_code == UET_NO_CCC_AVAIL || 
                nack_code == UET_NO_BITMAP || 
                nack_code == UET_INV_DPDCID || 
                nack_code == UET_PDC_HDR_MISMATCH || 
                nack_code == UET_NO_RESOURCE);
    }

    // ==================== Common implemented functions ====================
    
    /**
     * @brief Process received request Process received request Process received request
     * @param pkt Received network packet Received network packet
     * @return Processing result handle Processing result handle
     */
    uint16_t processRxReq(PDStoNET_pkt *pkt);

    /**
     * @brief Update sending PSN tracker Update sending PSN tracker Update sending PSN tracker
     */
    void updateTxPsnTracker();

    /**
     * @brief Update sending PSN tracker with parameters Update sending PSN tracker with parameters Update sending PSN tracker（带参数版本）
     * @param psn Packet sequence number Packet sequence number
     * @param ack_req_flag ACK request flag ACK request flag
     * @param cack_psn Cumulative ACK PSN Cumulative ACK PSN
     */
    void updateTxPsnTracker(uint32_t psn, uint8_t ack_req_flag, uint32_t cack_psn);
    /**
     * @brief Update receiving PSN tracker Update receiving PSN tracker Update receiving PSN tracker
     * @param meta Received packet metadata Received packet metadata
     */
    void updateRxPsnTracker(RX_pkt_meta *meta);

    /**
     * @brief Update receiving PSN tracker Update receiving PSN tracker Update receiving PSN tracker
     * @param meta Received packet metadata Received packet metadata
     * @param gtd_del Guaranteed delivery flag Guaranteed delivery flag
     */
    void updateRxPsnTracker(RX_pkt_meta *meta, bool gtd_del);

    /**
     * @brief Retransmit specified PSN packet Retransmit specified PSN packet Retransmit specified PSN packet
     * @param psn Packet sequence number Packet sequence number
     */
    void reTx(uint32_t psn);

    /**
     * @brief Handle transmission timeout Handle transmission timeout Handle transmission timeout
     * @param psn Timeout packet sequence number 超时的Packet sequence number
     */
    void txRto(uint32_t psn);


    /**
     * @brief Release PDC resources Release PDC resources Release PDC resources
     */
    void freePDC();
    /**
     * @brief Send NACK response Send NACK response Send NACK response
     * @param rsp Response packet Response packet
     */
    void txNack(SES_PDC_rsp *rsp);
    /**
     * @brief Process control packet generation and sending Process control packet generation and sending Process control packet generation and sending
     */
    void txCtrl();
    /**
     * @brief Forward request to SES layer Forward request to SES layer Forward request to SES layer
     * @param handle Request handle Request handle
     * @param meta Packet metadata Packet metadata
     * @param pkt Packet data Packet data
     */
    void fwdReq2SES(uint16_t handle, RX_pkt_meta meta, SEStoPDS_pkt *pkt);

    /**
     * @brief Forward response to SES layer Forward response to SES layer Forward response to SES layer
     * @param pkt Response packet pointer Response packet指针
     */
    void fwdRsp2SES(const PDStoNET_pkt *pkt);

    /**
     * @brief Check reception error Check reception error Check reception error
     * @param pkt Received packet Received packet
     */
    void chkRxError(PDStoNET_pkt *pkt);
    /**
     * @brief Process NOOP control message Process NOOP control message Process NOOP control message
     * @param p Data packet to process Data packet to process
     */
    void rxCtrlNoop(PDStoNET_pkt *p);

    /**
     * @brief Process ACK_req control message Process ACK_req control message Process ACK_req control message
     * @param p Data packet to process Data packet to process
     */
    void rxCtrlAckReq(PDStoNET_pkt *p);
    void rxCtrlSack(PDStoNET_pkt *p);

    /**
     * @brief Process Clear_cmd control message Process Clear_cmd control message Process Clear_cmd control message
     * @param p Data packet to process Data packet to process
     */
    void rxCtrlClearCmd(PDStoNET_pkt *p);

    /**
     * @brief Process Clear_req control message Process Clear_req control message Process Clear_req control message
     * @param p Data packet to process Data packet to process
     */
    void rxCtrlClearReq(PDStoNET_pkt *p);
    /**
     * @brief Send close request packet Send close request packet Send close request packet
     */
    void sendCloseReq();
    /**
     * @brief Send close confirmation packet Send close confirmation packet Send close confirmation packet
     */
    void sendCloseAck();
    /**
     * @brief Send Noop control packet Send Noop control packet Send Noop control packet
     * @param p Control packet pointer Control packet pointer
     */
    void sendCtrlNoop(PDStoNET_pkt *p);
    /**
     * @brief Send ACK Request control packet Send ACK Request control packet Send ACK Request control packet
     * @param p Control packet pointer Control packet pointer
     */
    bool sendCtrlAckReq(PDStoNET_pkt *p);
    bool sendCtrlSack(PDStoNET_pkt *p);

    /**
     * @brief Send Clear Command control packet Send Clear Command control packet Send Clear Command control packet
     * @param p Control packet pointer Control packet pointer
     */
    void sendCtrlClearCmd(PDStoNET_pkt *p);

    /**
     * @brief Send Clear Request control packet Send Clear Request control packet Send Clear Request control packet
     * @param p Control packet pointer Control packet pointer
     */
    void sendCtrlClearReq(PDStoNET_pkt *p);
    /**
     * @brief Send Close_req control message Send Close_req control message Send Close_req control message
     * @param p Data packet to process Data packet to process
     */
    void sendCtrlCloseReq(PDStoNET_pkt *p);

    /**
     * @brief Send Credit control message Send Credit control message Send Credit control message
     * @param p Data packet to process Data packet to process
     * @warning TODO: We need to study credit-based flow control // TODO: We need to study credit-based flow control
     */
    bool sendCtrlCredit(PDStoNET_pkt *p);
    bool sendCtrlCreditReq(PDStoNET_pkt *p);

    /**
     * @brief Send Negotiation control message Send Negotiation control message Send Negotiation control message
     * @param p Data packet to process Data packet to process
     */
    void sendCtrlNegotiation(PDStoNET_pkt *p);

    /**
     * @brief Get unacknowledged packet count Get unacknowledged packet count 获取Unacknowledged packet count
     * @return Number of unacknowledged packets Number of unacknowledged packets
     */
    int getUnackCount() const;

    /**
     * @brief Get all acknowledgment status Get all acknowledgment status Get all acknowledgment status
     * @return Whether all are acknowledged Whether all are acknowledged
     */
    bool getAllACKStatus() const;
    
    /**
     * @brief Get open message count Get open message count 获取Open message count
     * @return Number of open messages Number of open messages
     */
    int getOpenMsgCount() const;

    /**
     * @brief Get PDC safe close status Get PDC safe close status Get PDC safe close status
     * @param unack_cnt_out Output unacknowledged packet count 输出Unacknowledged packet count
     * @param allACK_out Output all acknowledgment status Output all acknowledgment status
     * @param open_msg_out Output open message count 输出Open message count
     */
    void getCloseStatus(int& unack_cnt_out, bool& allACK_out, int& open_msg_out) const;

    
    /**
     * @brief Initialize PDC instance Initialize PDC instance Initialize PDC instance
     * @param id PDC identifier PDC identifier
     * @return Whether initialization is successful Whether initialization is successful
     */
    virtual bool initPDC(uint16_t id, pdc_mode init_mode) = 0;
    /**
     * @brief Main event loop Main event loop Main event loop
     */
    virtual void openChk() = 0;

    /**
     * @brief Process received request packet Process received request packet Process received request packet
     * @param pkt Request packet Request packet
     */
    virtual void rxReq(PDStoNET_pkt *pkt) = 0;

    /**
     * @brief Process received ACK packet Process received ACK包
     * @param pkt Received ACK packet Received ACK packet
     */
    virtual void rxAck(PDStoNET_pkt *pkt) = 0;

    /**
     * @brief Process received NACK packet Process received NACK包
     * @param pkt Received NACK packet Received NACK packet
     */
    void rxNack(PDStoNET_pkt *pkt);

    /**
     * @brief Process received control message Process received control message Process received control message
     * @param pkt Received control message packet Received control message packet
     */
    virtual void rxCtrl(PDStoNET_pkt *pkt) = 0;

    /**
     * @brief Send request packet Send request packet 发送Request packet
     * @param next_hdr Next header type Next header type
     * @param retx Retransmission flag Retransmission flag
     * @param ar ACK request flag ACK request flag
     * @param psn Packet sequence number Packet sequence number
     * @param syn SYN flag SYN flag
     * @param pkt Packet data Packet data
     */
    void sendReq(PDS_next_hdr next_hdr,uint8_t retx,uint8_t ar,uint32_t psn,uint8_t syn,const SEStoPDS_pkt *pkt);
    /**
     * @brief Send ACK packet Send ACK packet Send ACK packet
     * @param next_hdr Next header type Next header type
     * @param retx Retransmission flag Retransmission flag
     * @param req ACK request flag Request flag
     * @param psn Packet sequence number Packet sequence number
     * @param pkt Packet data Packet data
     * @param gtd_del Guaranteed delivery flag Guaranteed delivery flag
     */
    void sendAck(PDS_next_hdr next_hdr,
                 uint8_t retx,
                 uint8_t req,
                 uint32_t psn,
                 SEStoPDS_pkt *pkt,
                 bool gtd_del,
                 uint32_t credit_job_id = 0);
    /**
     * @brief Send NACK packet Send NACK包
     * @param retx Retransmission flag Retransmission flag
     * @param nack_psn NACK PSN NACK PSN
     * @param nack_code NACK error code NACK error code
     * @param payload Payload data Payload data
     * @param pkt Packet data Packet data
     */
    void sendNack(uint8_t retx, uint32_t nack_psn, PDS_Nack_Codes nack_code, uint32_t payload,SEStoPDS_pkt *pkt);
    /**
     * @brief Send request to network layer Send request to network layer Send request to network layer
     * @param req Request packet Request packet
     */
    void txReq(PDS_PDC_req *req);
    /**
     * @brief Send response to network layer Send response to network layer Send response to network layer
     * @param rsp Response packet Response packet
     */
    void txRsp(SES_PDC_rsp *rsp);
    /**
     * @brief Set public queues Set public queues Set public queues
     * @param net_q Network queue Network queue
     * @param ses_req_q SES request queue SES request queue
     * @param ses_rsp_q SES response queue SES response queue
     * @param close_q Close queue Close queue
     */
    void setPublicQueues(ThreadSafeQueue<PDStoNET_pkt>* net_q,
                        ThreadSafeQueue<PDC_SES_req>* ses_req_q,
                        ThreadSafeQueue<PDC_SES_rsp>* ses_rsp_q,
                        ThreadSafeQueue<uint16_t>* close_q);

    int64_t nowMs() const;
    void markActivity();
    void incPending();
    void decPending();

    /**
     * @brief Check if PDC can safely close Check if PDC can safely close Check if PDC can safely close
     * @return Whether it can be closed safely Whether it can be closed safely
     */
    bool canSafelyClose();
    bool isRudMode() const;
    bool packetModeMatches(const PDStoNET_pkt *pkt) const;
    pdc_mode packetMode(const PDStoNET_pkt *pkt) const;
    static bool hasRxCallbacks();
    void resetRudState();
    void advanceRudRxFrontier();
    void refreshRudGapState();
    uint32_t buildRudSackBitmap(uint32_t *base_psn_out = nullptr) const;
    void noteRudSackPending();
    void noteRudGapPending();
    void maybeTriggerRudControl();
    bool canDispatchFrontReq(const PDS_PDC_req &req, int64_t now_ms);
    void rxAckControlExt(const PDStoNET_pkt *pkt);
    void rxCtrlCredit(PDStoNET_pkt *p);
    void rxCtrlCreditReq(PDStoNET_pkt *p);
    bool handleRudRxRequest(PDStoNET_pkt *pkt);
    bool handleRudRxResponse(const PDStoNET_pkt *pkt);
    void applyRudSack(uint32_t base_psn, uint32_t bitmap);

    // ==================== Timer management functions Timer management functions Timer management functions ====================
    
    /**
     * @brief Start packet timer Start packet timer Start packet timer
     * @param psn Packet sequence number Packet sequence number
     * @param retry_count Current retry count Current retry count
     */
    void startPacketTimer(uint32_t psn, uint16_t retry_count = 0);
    
    /**
     * @brief Stop packet timer Stop packet timer Stop packet timer
     * @param psn Packet sequence number Packet sequence number
     */
    void stopPacketTimer(uint32_t psn);
    
    /**
     * @brief Update packet RTO time Update packet RTO time Update packet RTO time
     * @param psn Packet sequence number Packet sequence number
     * @param new_rto New RTO time New RTO time
     */
    void updatePacketRTO(uint32_t psn, uint16_t new_rto);
    
    /**
     * @brief Clear all packet timers Clear all packet timers Clear all packet timers
     */
    void clearAllPacketTimers();
    
    /**
     * @brief Get timer information Get timer information Get timer information
     * @param psn Packet sequence number Packet sequence number
     * @return Timer information Timer information Timer information
     */
    RTOTimer::TimerItem getTimerInfo(uint32_t psn) const;
    
    /**
     * @brief Check if timer is active Check if timer is active Check if timer is active
     * @param psn Packet sequence number Packet sequence number
     * @return Whether it is active Whether it is active
     */
    bool isTimerActive(uint32_t psn) const;
    
    /**
     * @brief Get active timer count Get active timer count Get active timer count
     * @return Number of active timers Number of active timers
     */
    size_t getActiveTimerCount() const;

    /**
     * @brief Check and clear PDC status Check and clear PDC status Check and clear PDC status
     */
    void chkClear();
    /**
     * @brief Check and process PDC trimming status Check and process PDC trimming status Check and process PDC trimming status
     * @return Whether trimming is processed Whether trimming is processed
     */
    bool chkTrim();
    /**
     * @brief Set FEP address Set FEP address Set FEP address
     * @param dst Destination IP address Destination IP address
     * @param src Source IP address Source IP address
     */
    void setFep(uint32_t dst, uint32_t src);

private:
    static int64_t rudSackRefreshMs();
    static int controlPriority(cm_type type);
    static NackCtrlClass classifyNack(PDS_Nack_Codes nack_code);
    bool shouldSendAckReq(uint32_t req_psn, int64_t now_ms);
    bool shouldSendSack(uint32_t base_psn, uint32_t bitmap, int64_t now_ms);
    bool shouldSendGapNack(int64_t now_ms);
    bool selectRudReadResponseGap(uint32_t *gap_psn_out, int64_t now_ms);
    bool shouldSendRecoverableNack(PDS_Nack_Codes nack_code,
                                   uint32_t nack_psn,
                                   uint32_t payload,
                                   int64_t now_ms);
    void noteAckReqSent(uint32_t req_psn, int64_t now_ms);
    void noteSackSent(uint32_t base_psn, uint32_t bitmap, int64_t now_ms);
    void noteGapNackSent(int64_t now_ms);
    void noteGapNackSuppressed();
    bool requestControl(cm_type type);
    void refillCtrlBudget(int64_t now_ms);
    bool tryConsumeCtrlBudget(cm_type type, int64_t now_ms);
    bool tryConsumeGapNackBudget(int64_t now_ms);
    bool hasCreditRefreshActivity() const;
    bool maybeScheduleCreditRefresh(int64_t now_ms);
    bool tryConsumeBudgetClassB(int64_t now_ms);
    bool tryConsumeBudgetClassC(int64_t now_ms);
    static int64_t creditRefreshMs();
    static int64_t creditReqDelayMs();
    static bool isNewerCreditGen(uint16_t newer, uint16_t older);
    uint16_t computePostedRecvCredits(uint32_t job_id) const;
    uint16_t computeUnexpectedMsgCredits() const;
    uint16_t computeUnexpectedByteCredits() const;
    uint16_t computeUnexpectedMsgsInUse() const;
    uint16_t computeBitmapBlocksAvailable() const;
    uint16_t computeArrivalBlocksAvailable() const;
    void observeReceiverJob(uint32_t job_id);
    LocalReceiverCreditState &localCreditStateForJob(uint32_t job_id);
    PeerReceiverCreditState &peerCreditStateForJob(uint32_t job_id);
    bool refreshLocalCreditForJob(uint32_t job_id, int64_t now_ms);
    bool hasDirtyLocalCreditJob() const;
    bool selectCreditJobForAck(uint32_t ack_job_id, int64_t now_ms, uint32_t *job_id_out);
    bool selectStandaloneCreditJob(int64_t now_ms, uint32_t *job_id_out);
    bool maybeFillAckControlExt(PDStoNET_pkt *ack, int64_t now_ms, uint32_t ack_job_id);
    void clearPendingSackControlIfMatching();
    void encodeCreditSnapshotPayload(UET::PayloadHandle &payload,
                                     const ReceiverFlowCreditSnapshot &snapshot) const;
    bool decodeCreditSnapshotPayload(const UET::PayloadHandle &payload,
                                     ReceiverFlowCreditSnapshot *snapshot) const;
    void encodeCreditReqPayload(UET::PayloadHandle &payload, uint32_t job_id, uint16_t last_seen_credit_gen) const;
    bool decodeCreditReqPayload(const UET::PayloadHandle &payload,
                                uint32_t *job_id,
                                uint16_t *last_seen_credit_gen) const;
    enum class ChunkArrivalResult : uint8_t
    {
        ALREADY_ARRIVED = 0x00,
        MARKED_OK = 0x01,
        NO_BITMAP = 0x02,
    };

    static ResolveRxRequestPlacementFn resolve_rx_request_placement_;
    static ResolveRxResponsePlacementFn resolve_rx_response_placement_;
    static CompleteRxOperationFn complete_rx_operation_;
    static CompleteRequestTerminalFn complete_request_terminal_;
    static CompleteSenderTerminalFn complete_sender_terminal_;
    static CompleteReadResponseTerminalFn complete_read_response_terminal_;
    static ResolvePostedRecvCreditsFn resolve_posted_recv_credits_;

    PDC_SES_req buildSesReq(uint16_t handle, const RX_pkt_meta &meta, const SEStoPDS_pkt &pkt) const;
    PDC_SES_rsp buildSesRsp(const PDStoNET_pkt *pkt) const;
    bool shouldOwnRudRequest(const PDStoNET_pkt *pkt) const;
    bool shouldOwnRudResponse(const PDStoNET_pkt *pkt) const;
    uint32_t payloadChunkSizeForRequest(const PDC_SES_req &req) const;
    uint32_t payloadChunkSizeForResponse(const PDC_SES_rsp &rsp) const;
    RxMessageKey buildRxMessageKey(const PDC_SES_req &req) const;
    RxMessageKey buildRxMessageKey(const PDC_SES_rsp &rsp) const;
    bool ensureRxMessageContext(const PDC_SES_req &req,
                                uint32_t base_psn,
                                uint16_t rx_pkt_handle,
                                RxMessageContext *&ctx_out);
    bool ensureRxMessageContext(const PDC_SES_rsp &rsp, RxMessageContext *&ctx_out);
    uint16_t cacheResponseHandle(const PDStoNET_pkt *pkt);
    void eraseRxHandle(uint16_t handle);
    RudBitmapBlock *findHotArrivalBlock(RxMessageContext &ctx, uint32_t block_base);
    RudBitmapBlock *getArrivalBlock(RxMessageContext &ctx, uint32_t block_base, bool create_if_missing);
    ChunkArrivalResult markChunkArrived(RxMessageContext &ctx, uint32_t chunk_idx);
    bool isChunkArrived(const RxMessageContext &ctx, uint32_t chunk_idx) const;
    void advanceMessageFrontier(RxMessageContext &ctx);
    void pruneCompletedArrivalBlocks(RxMessageContext &ctx);
    void emitRxCompletion(const RxMessageKey &key,
                          const RxMessageContext &ctx,
                          PDC_RX_completion_type type,
                          uint8_t return_code,
                          bool success,
                          PDC_RX_completion_notify_kind notify_kind,
                          uint32_t modified_length,
                          PDC_RX_failure_kind failure_kind = PDC_RX_failure_kind::SEMANTIC,
                          PDS_Nack_Codes pds_nack_code = UET_NO_RESOURCE);
    void releaseRxMessageContext(const RxMessageKey &key,
                                 RxMessageContext &ctx,
                                 RudReleaseReason reason = RudReleaseReason::NORMAL);
    void completeRxMessage(const RxMessageKey &key,
                           RxMessageContext &ctx,
                           PDC_RX_completion_type type,
                           uint8_t return_code,
                           bool success,
                           PDC_RX_completion_notify_kind notify_kind = PDC_RX_completion_notify_kind::OP_COMPLETE,
                           uint32_t modified_length = 0,
                           PDC_RX_failure_kind failure_kind = PDC_RX_failure_kind::SEMANTIC,
                           PDS_Nack_Codes pds_nack_code = UET_NO_RESOURCE);
    bool extractSenderTerminalFromReq(const PDS_PDC_req &req, SenderTerminalCompletion *completion) const;
    bool emitRequestTerminalCompletion(const RequestTerminalCompletion &completion);
    bool emitRequestTerminalCompletion(const TX_pkt_meta &meta, SenderTerminalReason reason);
    size_t terminalizeOutstandingRequests(SenderTerminalReason reason);
    bool emitSenderTerminalCompletion(const SenderTerminalCompletion &completion);
    bool emitSenderTerminalCompletion(const TX_pkt_meta &meta, SenderTerminalReason reason);
    size_t terminalizeOutstandingSenderRetries(SenderTerminalReason reason);
    bool extractReadResponseTerminalFromRsp(const SES_PDC_rsp &rsp, ReadResponseTerminalCompletion *completion) const;
    bool emitReadResponseTerminalCompletion(const ReadResponseTerminalCompletion &completion);
    bool emitReadResponseTerminalCompletion(const TX_pkt_meta &meta, ReadResponseTerminalReason reason);
    size_t terminalizeOutstandingReadResponses(ReadResponseTerminalReason reason);
    void reapUnexpectedPartialState();
    void pruneCompletedSendTombstones(int64_t now_ms);
    void rememberCompletedSendTombstone(const RxMessageKey &key, uint32_t modified_length, int64_t completed_at_ms);
    bool replayCompletedSendDuplicate(const RxMessageKey &key, uint16_t rx_pkt_handle);

protected:
    bool directPlaceRudWrite(PDStoNET_pkt *pkt, uint16_t handle, const RX_pkt_meta &meta);
    bool directPlaceRudSend(PDStoNET_pkt *pkt, uint16_t handle, const RX_pkt_meta &meta);
    bool directPlaceRudResponse(const PDStoNET_pkt *pkt);
    bool consumeSkipCtrlEmitOnce();

private:
    bool bindUnexpectedSend(const RxMessageKey &key, uint64_t completion_key, uint64_t base_addr, uint32_t buffer_len);
    void copyArrivedSendChunks(const RxMessageContext &ctx, uint8_t *dst) const;
    uint32_t expectedChunks(uint32_t total_len, uint32_t chunk_size) const;
    RequestTxProbe buildRequestTxProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep) const;
    static UnexpectedSendProbe buildUnexpectedSendProbe(const RxMessageContext &ctx);
};

// Default parameter definitions (using macro definitions to avoid duplicate definition errors) Default parameter definitions (using macro definitions to avoid duplicate definition errors)
#ifndef Default_MPR
#define Default_MPR 16               /**< Default maximum unacknowledged packet count 默认最大Number of unacknowledged packets */
#endif

#ifndef Max_RTO_Retx_Cnt
#define Max_RTO_Retx_Cnt 3           /**< Maximum retransmission count Maximum retransmission count */
#endif

#ifndef Base_RTO
#define Base_RTO 100                 /**< Base RTO time Base RTO time */
#endif

#ifndef Enb_ACK_Per_Pkt
#define Enb_ACK_Per_Pkt false        /**< Whether to enable per-packet ACK Whether to enable per-packet ACK */
#endif

#ifndef ACK_Gen_Min_Pkt_Add
#define ACK_Gen_Min_Pkt_Add 128       /**< Minimum packet increment for ACK generation Minimum packet increment */
#endif

#ifndef ACK_Gen_Trigger
#define ACK_Gen_Trigger 1024          /**< ACK generation trigger threshold ACK generation trigger threshold */
#endif

#endif // PDC_HPP
