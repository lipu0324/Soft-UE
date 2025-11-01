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
#include <cstdint>
#include <queue>
#include <map>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>

// Retransmission configuration
#define USE_RTO 0

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
    DROP,       /**< Packet drop error */
    INV_SYN,    /**< Invalid SYN flag */
    INV_DPDCID  /**< Invalid target PDCID */
};


/**
 * @brief PDC state to string conversion
 */
inline std::string pdcStateToString(pdc_state state) {
    switch (state) {
        case CLOSED:         return "CLOSED";
        case CREATING:       return "CREATING";
        case ESTABLISHED:    return "ESTABLISHED";
        case QUIESCE:        return "QUIESCE";
        case ACK_WAIT:       return "ACK_WAIT";
        case CLOSE_ACK_WAIT: return "CLOSE_ACK_WAIT";
        case PENDING:        return "PENDING";
        default:             return "UNKNOWN_STATE(" + std::to_string(static_cast<int>(state)) + ")";
    }
}

/**
 * @brief PDC mode to string conversion
 */
inline std::string pdcModeToString(pdc_mode mode) {
    switch (mode) {
        case RUD:  return "RUD";
        case ROD:  return "ROD";
        case RUDI: return "RUDI";
        case UUD:  return "UUD";
        default:   return "UNKNOWN_MODE(" + std::to_string(static_cast<int>(mode)) + ")";
    }
}

/**
 * @brief Control message type to string conversion Control message type to string conversion Control message type to string conversion 
 */
inline std::string cmTypeToString(cm_type type) {
    switch (type) {
        case NOOP:        return "NOOP";
        case ACK_REQ:     return "ACK_REQ";
        case CLR_CMD:     return "CLEAR_CMD";
        case CLR_REQ:     return "CLEAR_REQ";
        case CLOSE_CMD:   return "CLOSE_CMD";
        case CLOSE_REQ:   return "CLOSE_REQ";
        case PROBE:       return "PROBE";
        case CREDIT:      return "CREDIT";
        case CREDIT_REQ:  return "CREDIT_REQ";
        case NEGOTIATION: return "NEGOTIATION";
        case NONE:        return "NONE";
        default:          return "UNKNOWN_CM_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

/**
 * @brief Error type to string conversion Error type to string conversion Error type to string conversion 
 */
inline std::string errorTypeToString(error_type type) {
    switch (type) {
        case OPEN:       return "OPEN";
        case ACK_ERROR:  return "ACK_ERROR";
        case OOO:        return "OOO";
        case DROP:       return "DROP";
        case INV_SYN:    return "INV_SYN";
        case INV_DPDCID: return "INV_DPDCID";
        default:         return "UNKNOWN_ERROR_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

/**
 * @brief PDS packet type to string conversion PDS packet type to string conversion 
 */
inline std::string pdsTypeToString(PDS_type type) {
    switch (type) {
        case Reserved:    return "Reserved";
        case TSS:         return "TSS";
        case RUD_REQ:     return "RUD_REQ";
        case ROD_REQ:     return "ROD_REQ";
        case RUDI_REQ:    return "RUDI_REQ";
        case RUDI_RESP:   return "RUDI_RESP";
        case UUD_REQ:     return "UUD_REQ";
        case ACK:         return "ACK";
        case ACK_CC:      return "ACK_CC";
        case ACK_CCX:     return "ACK_CCX";
        case NACK:        return "NACK";
        case CP:          return "CP";
        case NACK_CCX:    return "NACK_CCX";
        case RUD_CC_REQ:  return "RUD_CC_REQ";
        case ROD_CC_REQ:  return "ROD_CC_REQ";
        default:          return "UNKNOWN_PDS_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

/**
 * @brief PDS header type to string conversion PDS header type to string conversion 
 */
inline std::string pdsHeaderTypeToString(PDS_header_type type) {
    switch (type) {
        case entropy_header:   return "entropy_header";
        case RUOD_req_header:  return "RUOD_req_header";
        case RUOD_ack_header:  return "RUOD_ack_header";
        case RUOD_cp_header:   return "RUOD_cp_header";
        case nack_header:      return "nack_header";
        default:               return "UNKNOWN_HEADER_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

/**
 * @brief PDS next header type to string conversion PDS next header type to string conversion 
 */
inline std::string pdsNextHdrToString(PDS_next_hdr type) {
    switch (type) {
        case UET_HDR_REQUEST_SMALL:      return "UET_HDR_REQUEST_SMALL";
        case UET_HDR_REQUEST_MEDIUM:     return "UET_HDR_REQUEST_MEDIUM";
        case UET_HDR_REQUEST_STD:        return "UET_HDR_REQUEST_STD";
        case UET_HDR_RESPONSE:           return "UET_HDR_RESPONSE";
        case UET_HDR_RESPONSE_DATA:      return "UET_HDR_RESPONSE_DATA";
        case UET_HDR_RESPONSE_DATA_SMALL: return "UET_HDR_RESPONSE_DATA_SMALL";
        case UET_HDR_NONE:               return "UET_HDR_NONE";
        default:                         return "UNKNOWN_NEXT_HDR(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

/**
 * @brief PDS control type to string conversion PDS control type to string conversion 
 */
inline std::string pdsCtlTypeToString(PDS_ctl_type type) {
    switch (type) {
        case Noop:        return "Noop";
        case ACK_req:     return "ACK_req";
        case Clear_cmd:   return "Clear_cmd";
        case Clear_req:   return "Clear_req";
        case Close_cmd:   return "Close_cmd";
        case Close_req:   return "Close_req";
        case Probe:       return "Probe";
        case Credit:      return "Credit";
        case Credit_req:  return "Credit_req";
        case Negotiation: return "Negotiation";
        default:          return "UNKNOWN_CTL_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

/**
 * @brief NACK code to string conversion NACK code to string conversion 
 */
inline std::string nackCodeToString(PDS_Nack_Codes code) {
    switch (code) {
        case UET_TRIMMED:           return "UET_TRIMMED";
        case UET_TRIMMED_LASTHOP:   return "UET_TRIMMED_LASTHOP";
        case UET_TRIMMED_ACK:       return "UET_TRIMMED_ACK";
        case UET_NO_PDC_AVAIL:      return "UET_NO_PDC_AVAIL";
        case UET_NO_CCC_AVAIL:      return "UET_NO_CCC_AVAIL";
        case UET_NO_BITMAP:         return "UET_NO_BITMAP";
        case UET_NO_PKT_BUFFER:     return "UET_NO_PKT_BUFFER";
        case UET_NO_GTD_DEL_AVAIL:  return "UET_NO_GTD_DEL_AVAIL";
        case UET_NO_SES_MSG_AVAIL:  return "UET_NO_SES_MSG_AVAIL";
        case UET_NO_RESOURCE:       return "UET_NO_RESOURCE";
        case UET_PSN_OOR_WINDOW:    return "UET_PSN_OOR_WINDOW";
        case reserved:              return "reserved";
        case UET_ROD_OOO:           return "UET_ROD_OOO";
        case UET_INV_DPDCID:        return "UET_INV_DPDCID";
        case UET_PDC_HDR_MISMATCH:  return "UET_PDC_HDR_MISMATCH";
        case UET_CLOSING:           return "UET_CLOSING";
        case UET_CLOSING_IN_ERR:    return "UET_CLOSING_IN_ERR";
        case UET_PKT_NOT_RCVD:      return "UET_PKT_NOT_RCVD";
        case UET_GTD_RESP_UNAVAIL:  return "UET_GTD_RESP_UNAVAIL";
        case UET_ACK_WITH_DATA:     return "UET_ACK_WITH_DATA";
        case UET_INVALID_SYN:       return "UET_INVALID_SYN";
        case UET_PDC_MODE_MISMATCH: return "UET_PDC_MODE_MISMATCH";
        case UET_NEW_START_PSN:     return "UET_NEW_START_PSN";
        case UET_RCVD_SES_PROCG:    return "UET_RCVD_SES_PROCG";
        case UET_UNEXP_EVENT:       return "UET_UNEXP_EVENT";
        case UET_RCVR_INFER_LOSS:   return "UET_RCVR_INFER_LOSS";
        default:                    return "UNKNOWN_NACK_CODE(0x" + 
                                           std::to_string(static_cast<int>(code)) + ")";
    }
}
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
    // Add any other metadata you need to store here 
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
    uint32_t psn;           /**< Packet sequence number (PSN) */
    uint32_t clear_psn;     /**< Clear PSN, used for flow control */
    uint8_t syn : 1;        /**< SYN flag (establish connection) */
    uint8_t retx : 1;       /**< Retransmission flag */
    uint8_t ar : 1;         /**< ACK request flag */
    bool som;               /**< Message start flag (Start Of Message) */
    uint16_t payload_len;   /**< Payload length */
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
    // Queues and mapping tables
    std::map<uint32_t, TX_pkt_meta> tx_pkt_map;       /**< Store metadata of sent packets */
    std::map<uint16_t, RX_pkt_meta> rx_pkt_map;       /**< Store metadata of received packets */
    std::map<uint32_t, PDStoNET_pkt> tx_pkt_buffer;   /**< Store unacknowledged request packets */
    std::map<uint32_t, PDStoNET_pkt> tx_ack_buffer;   /**< Store guaranteed delivery ACK packets */
    const unsigned int tx_ack_buffer_capa = 10;                /**< ACK buffer capacity */


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

    // Public queue pointers  
    ThreadSafeQueue<PDStoNET_pkt>* public_net_queue = nullptr;
    ThreadSafeQueue<PDC_SES_req>* public_ses_req_queue = nullptr;
    ThreadSafeQueue<PDC_SES_rsp>* public_ses_rsp_queue = nullptr;
    ThreadSafeQueue<uint16_t>* public_close_queue = nullptr;

    // ==================== Constructors and Destructors ====================
    PDC();
    virtual ~PDC();

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
    void fwdRsp2SES(SEStoPDS_pkt *pkt);

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
    void sendCtrlAckReq(PDStoNET_pkt *p);

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
    void sendCtrlCredit(PDStoNET_pkt *p);

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
    virtual bool initPDC(uint16_t id) = 0;
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
    void sendAck(PDS_next_hdr next_hdr,uint8_t retx,uint8_t req,uint32_t psn,SEStoPDS_pkt *pkt,bool gtd_del);
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

    /**
     * @brief Check if PDC can safely close Check if PDC can safely close Check if PDC can safely close
     * @return Whether it can be closed safely Whether it can be closed safely
     */
    bool canSafelyClose();

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