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
 * @file             LoggingEnhancer.hpp
 * @brief            LoggingEnhancer.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This header provides enhanced logging macros and utilities for TPDC debugging and performance monitoring.
 */


#ifndef LOGGING_ENHANCER_HPP
#define LOGGING_ENHANCER_HPP

#include "Logger.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include <sstream>
#include <iomanip>


/**
 * @brief Parameter logging macros
 */
#define LOG_PARAM(name, value) do { \
    std::stringstream ss; \
    ss << #name << ": " << value; \
    LOG_DEBUG(__FUNCTION__, ss.str()); \
} while(0)

#define LOG_PARAM_HEX(name, value) do { \
    std::stringstream ss; \
    ss << #name << ": 0x" << std::hex << value; \
    LOG_DEBUG(__FUNCTION__, ss.str()); \
} while(0)

#define LOG_PARAM_BOOL(name, value) do { \
    std::stringstream ss; \
    ss << #name << ": " << (value ? "true" : "false"); \
    LOG_DEBUG(__FUNCTION__, ss.str()); \
} while(0)

/**
 * @brief State change logging macro
 */
#define LOG_STATE_CHANGE(old_state, new_state) do { \
    std::stringstream ss; \
    ss << "State change: " << old_state << " -> " << new_state; \
    LOG_INFO(__FUNCTION__, ss.str()); \
} while(0)

/**
 * @brief Queue status logging macro
 */
#define LOG_QUEUE_STATUS(queue_name, queue) do { \
    std::stringstream ss; \
    ss << queue_name << " queue size: " << queue.size(); \
    LOG_DEBUG(__FUNCTION__, ss.str()); \
} while(0)

/**
 * @brief Packet information logging macro
 */
#define LOG_PACKET_INFO(pkt) do { \
    if (pkt) { \
        std::stringstream ss; \
        ss << "Packet info - Type: " << pkt->PDS_type; \
        if (pkt->PDS_type == RUOD_req_header) { \
            ss << ", PSN: " << pkt->PDS_header.RUOD_req_header.psn \
               << ", SPDCID: " << pkt->PDS_header.RUOD_req_header.spdcid \
               << ", DPDCID: " << pkt->PDS_header.RUOD_req_header.dpdcid \
               << ", SYN: " << (pkt->PDS_header.RUOD_req_header.flags.syn ? "1" : "0") \
               << ", AR: " << (pkt->PDS_header.RUOD_req_header.flags.ar ? "1" : "0") \
               << ", RETX: " << (pkt->PDS_header.RUOD_req_header.flags.retx ? "1" : "0"); \
        } else if (pkt->PDS_type == RUOD_ack_header) { \
            ss << ", ACK_PSN: " << (pkt->PDS_header.RUOD_ack_header.cack_psn + pkt->PDS_header.RUOD_ack_header.ack_psn_off) \
               << ", CACK_PSN: " << pkt->PDS_header.RUOD_ack_header.cack_psn \
               << ", SPDCID: " << pkt->PDS_header.RUOD_ack_header.spdcid \
               << ", DPDCID: " << pkt->PDS_header.RUOD_ack_header.dpdcid; \
        } else if (pkt->PDS_type == nack_header) { \
            ss << ", NACK_PSN: " << pkt->PDS_header.nack_header.nack_psn \
               << ", NACK_CODE: 0x" << std::hex << (int)pkt->PDS_header.nack_header.nack_code \
               << ", SPDCID: " << pkt->PDS_header.nack_header.spdcid \
               << ", DPDCID: " << pkt->PDS_header.nack_header.dpdcid; \
        } \
        LOG_INFO(__FUNCTION__, ss.str()); \
    } else { \
        LOG_ERROR(__FUNCTION__, "Packet pointer is null"); \
    } \
} while(0)

/**
 * @brief Error condition checking macros
 */
#define LOG_ERROR_CHECK(condition, message) do { \
    if (condition) { \
        LOG_ERROR(__FUNCTION__, message); \
        return; \
    } \
} while(0)

#define LOG_ERROR_CHECK_RETURN(condition, message, return_value) do { \
    if (condition) { \
        LOG_ERROR(__FUNCTION__, message); \
        return return_value; \
    } \
} while(0)

/**
 * @brief Performance critical path logging macro
 */
#define LOG_CRITICAL_PATH(message) do { \
    std::stringstream ss; \
    ss << "[CRITICAL] " << message; \
    LOG_INFO(__FUNCTION__, ss.str()); \
} while(0)

/**
 * @brief Memory operation logging macro
 */
#define LOG_MEMORY_OP(operation, size) do { \
    std::stringstream ss; \
    ss << "Memory operation: " << operation << ", size: " << size << " bytes"; \
    LOG_DEBUG(__FUNCTION__, ss.str()); \
} while(0)

/**
 * @brief Network operation logging macro
 */
#define LOG_NETWORK_OP(operation, bytes) do { \
    std::stringstream ss; \
    ss << "Network operation: " << operation << ", bytes: " << bytes; \
    LOG_INFO(__FUNCTION__, ss.str()); \
} while(0)

/**
 * @brief Function return value logging macro
 */
#define LOG_RETURN_VALUE(value) do { \
    std::stringstream ss; \
    ss << "Return value: " << value; \
    LOG_DEBUG(__FUNCTION__, ss.str()); \
} while(0)

/**
 * @brief Conditional branch logging macro
 */
#define LOG_BRANCH(condition, true_msg, false_msg) do { \
    if (condition) { \
        LOG_DEBUG(__FUNCTION__, true_msg); \
    } else { \
        LOG_DEBUG(__FUNCTION__, false_msg); \
    } \
} while(0)

/**
 * @class FunctionProfiler
 * @brief Function performance profiler
 */
class FunctionProfiler {
private:
    std::string function_name;
    std::chrono::steady_clock::time_point start_time;
    bool enabled;

public:
    explicit FunctionProfiler(const std::string& func_name, bool enable = true) 
        : function_name(func_name), enabled(enable) {
        if (enabled) {
            start_time = std::chrono::steady_clock::now();
            std::stringstream ss;
            ss << "Function start: " << function_name;
            LOG_DEBUG("FunctionProfiler", ss.str());
        }
    }
    
    ~FunctionProfiler() {
        if (enabled) {
            auto end_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
                end_time - start_time).count();
            
            std::stringstream ss;
            ss << "Function complete: " << function_name
               << ", duration: " << duration << " μs";
            LOG_DEBUG("FunctionProfiler", ss.str());
        }
    }
    
    void checkpoint(const std::string& checkpoint_name) {
        if (enabled) {
            auto current_time = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
                current_time - start_time).count();
            
            std::stringstream ss;
            ss << "Checkpoint [" << checkpoint_name << "] reached, duration: " << duration << " μs";
            LOG_DEBUG(function_name.c_str(), ss.str());
        }
    }
};

/**
 * @brief Enhanced function timer macros
 */
#define ENHANCED_FUNCTION_TIMER() FunctionProfiler profiler(__FUNCTION__)
#define ENHANCED_FUNCTION_TIMER_DISABLED() FunctionProfiler profiler(__FUNCTION__, false)
#define FUNCTION_CHECKPOINT(name) profiler.checkpoint(name)

/**
 * @brief Data structure state logging utility
 */
class StateLogger {
public:
    /**
     * @brief Log T_PDC state
     */
    void logTPDCState(const std::string& function_name, 
                            uint16_t spdcid, uint16_t dpdcid,
                            int state, uint32_t tx_cur_psn, 
                            uint32_t rx_cur_psn, uint32_t clear_psn,
                            uint32_t cack_psn, int unack_cnt) {
        std::stringstream ss;
        ss << "T_PDC State - SPDCID: " << spdcid
           << ", DPDCID: " << dpdcid
           << ", State: " << state
           << ", TX_PSN: " << tx_cur_psn
           << ", RX_PSN: " << rx_cur_psn
           << ", Clear_PSN: " << clear_psn
           << ", CACK_PSN: " << cack_psn
           << ", Unack_Cnt: " << unack_cnt;
        Logger::log(LogLevel::INFO, function_name, ss.str());
    }
    
    /**
     * @brief Log queue states
     */
    void logQueueStates(const std::string& function_name, const T_PDC& tpdc) {
        std::stringstream ss;
        ss << "Queue states - tx_req_q: " << tpdc.tx_req_q.size()
           << ", tx_rsp_q: " << tpdc.tx_rsp_q.size()
           << ", rx_pkt_q: " << tpdc.rx_pkt_q.size()
           << ", tx_pkt_map: " << tpdc.tx_pkt_map.size()
           << ", rx_pkt_map: " << tpdc.rx_pkt_map.size()
           << ", tx_pkt_buffer: " << tpdc.tx_pkt_buffer.size()
           << ", tx_ack_buffer: " << tpdc.tx_ack_buffer.size();
        Logger::log(LogLevel::DEBUG, function_name, ss.str());
    }
};
/**
 * @brief Convenient state logging macros
 */
#define LOG_TPDC_STATE(spdcid, dpdcid, state, tx_psn, rx_psn, clear_psn, cack_psn, unack_cnt) \
    StateLogger::logTPDCState(__FUNCTION__, spdcid, dpdcid, state, tx_psn, rx_psn, clear_psn, cack_psn, unack_cnt)

#define LOG_ALL_QUEUE_STATES() StateLogger::logQueueStates(__FUNCTION__)

/**
 * @brief Conditional logging macro - logs only under specific conditions
 */
#define LOG_IF(condition, level, message) do { \
    if (condition) { \
        Logger::log(level, __FUNCTION__, message); \
    } \
} while(0)

/**
 * @brief Rate-limited logging macro - prevents excessive logging
 */
#define LOG_THROTTLED(level, message, max_count) do { \
    static int log_count = 0; \
    if (log_count < max_count) { \
        Logger::log(level, __FUNCTION__, message); \
        log_count++; \
    } else if (log_count == max_count) { \
        std::stringstream ss; \
        ss << message << " (subsequent identical logs will be suppressed)"; \
        Logger::log(level, __FUNCTION__, ss.str()); \
        log_count++; \
    } \
} while(0)

#endif // LOGGING_ENHANCER_HPP