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
 * @file             TPDCProcessManager.hpp
 * @brief            TPDCProcessManager.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This header defines the TPDC process manager for multi-threaded PDC instance management.
 */



#ifndef TPDC_PROCESS_MANAGER_HPP
#define TPDC_PROCESS_MANAGER_HPP

#include "../TPDC.hpp"
#include "../PDC.hpp"
#include "../../PDS.hpp"
#include <iostream>
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <memory>
#include <unordered_map>

/**
 * @class TPDCProcessManager
 * @brief TPDC process manager class
 *
 * Manages multiple TPDC instances, each running in an independent thread,
 * interacting with external systems through thread-safe queue mechanisms
 */
class TPDCProcessManager {
public:
    // Process state enumeration
    enum ProcessState {
        STOPPED,    // Stopped
        RUNNING,    // Running
        PAUSED,     // Paused
        STOPPING    // Stopping
    };

    // Public queue references (for inter-module communication)
    ThreadSafeQueue<PDStoNET_pkt>* pds_to_net_queue = nullptr;
    ThreadSafeQueue<PDC_SES_req>* pdc_to_ses_req_queue = nullptr;
    ThreadSafeQueue<PDC_SES_rsp>* pdc_to_ses_rsp_queue = nullptr;
    ThreadSafeQueue<uint16_t>*    PDC_close_q = nullptr;

    /**
     * @brief Set public queue references
     * @param pds_to_net PDStoNet queue
     * @param pdc_to_ses_req PDCtoSES_req queue
     * @param pdc_to_ses_rsp PDCtoSES_rsp queue
     */
    void setPublicQueues(
        ThreadSafeQueue<PDStoNET_pkt>* pds_to_net,
        ThreadSafeQueue<PDC_SES_req>* pdc_to_ses_req,
        ThreadSafeQueue<PDC_SES_rsp>* pdc_to_ses_rsp,
        ThreadSafeQueue<uint16_t>*    pdc_close_q
    ) {
        pds_to_net_queue = pds_to_net;
        pdc_to_ses_req_queue = pdc_to_ses_req;
        pdc_to_ses_rsp_queue = pdc_to_ses_rsp;
        PDC_close_q = pdc_close_q;
        LOG_DEBUG(__FUNCTION__, "TPDC process manager public queue references set");
    }

private:

    // TPDC process information structure
    struct TPDC_ProcessInfo {
        std::unique_ptr<T_PDC> tpdc_instance;           // TPDC instance
        std::unique_ptr<std::thread> process_thread;    // Processing thread
        std::atomic<ProcessState> state;                // Process state
        std::atomic<bool> should_stop;                  // Stop flag
        std::mutex process_mutex;                       // Process mutex
        std::condition_variable process_cv;             // Condition variable
        uint16_t pdcid;                                // PDC identifier
        std::chrono::steady_clock::time_point last_activity; // Last activity time
        
        TPDC_ProcessInfo(uint16_t id) : 
            tpdc_instance(std::make_unique<T_PDC>()),
            state(STOPPED),
            should_stop(false),
            pdcid(id),
            last_activity(std::chrono::steady_clock::now()) {}
    };

    // Manager member variables
    std::unordered_map<uint16_t, std::unique_ptr<TPDC_ProcessInfo>> tpdc_processes;
    std::mutex manager_mutex;                           // Manager mutex
    std::atomic<bool> manager_running;                  // Manager running status
    std::unique_ptr<std::thread> monitor_thread;       // Monitoring thread
    
    // Configuration parameters
    static constexpr std::chrono::milliseconds OPENCHK_INTERVAL{1};     // openchk call interval
    static constexpr std::chrono::seconds MONITOR_INTERVAL{5};          // Monitoring interval
    static constexpr std::chrono::seconds IDLE_TIMEOUT{300};            // Idle timeout

public:
    /**
     * @brief Constructor
     */
    TPDCProcessManager() : manager_running(false) {
        LOG_DEBUG(__FUNCTION__, "TPDC process manager initialized");
    }

    /**
     * @brief Destructor
     */
    ~TPDCProcessManager() {
        LOG_DEBUG(__FUNCTION__, "TPDC process manager destructor started");
        stop();
        LOG_DEBUG(__FUNCTION__, "TPDC process manager destroyed");
    }


    /**
     * @brief Start manager
     * @return Whether startup was successful
     */
    bool start() {
        std::lock_guard<std::mutex> lock(manager_mutex);
        
        if (manager_running.load()) {
            LOG_ERROR(__FUNCTION__, "Manager is already running");
            return false;
        }
        
        manager_running.store(true);
        
        // Start monitoring thread
        monitor_thread = std::make_unique<std::thread>(&TPDCProcessManager::monitorLoop, this);
        
        LOG_DEBUG(__FUNCTION__, "TPDC process manager started");
        return true;
    }

    /**
     * @brief Stop manager
     */
    void stop() {
        LOG_DEBUG(__FUNCTION__, "Stopping TPDC process manager...");
        
        manager_running.store(false);
        
        // Stop all TPDC processes
        {
            std::lock_guard<std::mutex> lock(manager_mutex);
            for (auto& [pdcid, process_info] : tpdc_processes) {
                if (process_info && process_info->state.load() != STOPPED) {
                    process_info->should_stop.store(true);
                    process_info->process_cv.notify_all();
                    
                    if (process_info->process_thread && process_info->process_thread->joinable()) {
                        process_info->process_thread->join();
                    }
                }
            }
            
            tpdc_processes.clear();
        }
        
        // Stop monitoring thread
        if (monitor_thread && monitor_thread->joinable()) {
            monitor_thread->join();
        }
        
        LOG_DEBUG(__FUNCTION__, "TPDC process manager stopped");
    }


    /**
     * @brief Create new TPDC process
     * @param pdcid PDC identifier
     * @return Whether creation was successful
     */
    bool createTPDCProcess(uint16_t pdcid, uint32_t dst_fep, uint32_t src_fep) {
        std::lock_guard<std::mutex> lock(manager_mutex);
        
        if (!manager_running.load()) {
            LOG_ERROR(__FUNCTION__, "Manager not running, cannot create process");
            return false;
        }
        
        // Check if already exists
        if (tpdc_processes.find(pdcid) != tpdc_processes.end()) {
            LOG_ERROR(__FUNCTION__, "Process for PDCID " + std::to_string(pdcid) + " already exists");
            return false;
        }
        
        // Create new process information
        auto process_info = std::make_unique<TPDC_ProcessInfo>(pdcid);
        
        // Initialize TPDC instance
        if (!process_info->tpdc_instance->initPDC(pdcid)) {
            LOG_ERROR(__FUNCTION__, "Failed to initialize TPDC instance, PDCID: " + std::to_string(pdcid));
            return false;
        }

        // Set TPDC instance public queue references
        process_info->tpdc_instance->setPublicQueues(
            pds_to_net_queue,
            pdc_to_ses_req_queue,
            pdc_to_ses_rsp_queue,
            PDC_close_q
        );
        LOG_DEBUG(__FUNCTION__, "TPDC instance public queue references set, PDCID: " + std::to_string(pdcid));
        
        // Set FEP addresses
        process_info->tpdc_instance->setFep(dst_fep, src_fep);
        LOG_DEBUG(__FUNCTION__, "TPDC instance FEP addresses set, PDCID: " + std::to_string(pdcid) + ", DST_FEP: " + std::to_string(dst_fep) + ", SRC_FEP: " + std::to_string(src_fep));
        
        // Start processing thread
        process_info->process_thread = std::make_unique<std::thread>(
            &TPDCProcessManager::tpdcProcessLoop, this, process_info.get());
        
        process_info->state.store(RUNNING);
        
        tpdc_processes[pdcid] = std::move(process_info);
        
        LOG_DEBUG(__FUNCTION__, "Successfully created TPDC process, PDCID: " + std::to_string(pdcid));
        return true;
    }

    /**
     * @brief Stop specified TPDC process
     * @param pdcid PDC identifier
     * @return Whether stop was successful
     */
    bool stopTPDCProcess(uint16_t pdcid) {
        std::lock_guard<std::mutex> lock(manager_mutex);
        
        auto it = tpdc_processes.find(pdcid);
        if (it == tpdc_processes.end()) {
            LOG_ERROR(__FUNCTION__, "PDCID not found: " + std::to_string(pdcid));
            return false;
        }
        
        auto& process_info = it->second;
        process_info->should_stop.store(true);
        process_info->state.store(STOPPING);
        process_info->process_cv.notify_all();
        
        if (process_info->process_thread && process_info->process_thread->joinable()) {
            process_info->process_thread->join();
        }
        
        process_info->state.store(STOPPED);
        LOG_DEBUG(__FUNCTION__, "Successfully stopped TPDC process, PDCID: " + std::to_string(pdcid));
        return true;
    }

    /**
     * @brief Pause specified TPDC process
     * @param pdcid PDC identifier
     * @return Whether pause was successful
     */
    bool pauseTPDCProcess(uint16_t pdcid) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(process_info->process_mutex);
        if (process_info->state.load() == RUNNING) {
            process_info->state.store(PAUSED);
            LOG_DEBUG(__FUNCTION__, "Paused TPDC process, PDCID: " + std::to_string(pdcid));
            return true;
        }
        return false;
    }

    /**
     * @brief Resume specified TPDC process
     * @param pdcid PDC identifier
     * @return Whether resume was successful
     */
    bool resumeTPDCProcess(uint16_t pdcid) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info) {
            return false;
        }
        
        std::lock_guard<std::mutex> lock(process_info->process_mutex);
        if (process_info->state.load() == PAUSED) {
            process_info->state.store(RUNNING);
            process_info->process_cv.notify_all();
            LOG_DEBUG(__FUNCTION__, "Resumed TPDC process, PDCID: " + std::to_string(pdcid));
            return true;
        }
        return false;
    }

    /**
     * @brief Get TPDC process status
     * @param pdcid PDC identifier
     * @return Process state
     */
    ProcessState getProcessState(uint16_t pdcid) {
        auto* process_info = getProcessInfo(pdcid);
        return process_info ? process_info->state.load() : STOPPED;
    }

    // ==================== Queue Interaction Interface ====================

    /**
     * @brief Add packet to specified TPDC receive queue
     * @param pdcid PDC identifier
     * @param pkt Data packet
     * @return Whether addition was successful
     */
    bool pushRxPacket(uint16_t pdcid, const PDStoNET_pkt& pkt) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info || process_info->state.load() != RUNNING) {
            return false;
        }
        
        // Thread-safely add to receive queue - use instance member queue
        process_info->tpdc_instance->rx_pkt_q.push(pkt);
        process_info->last_activity = std::chrono::steady_clock::now();
        return true;
    }

    /**
     * @brief Add request to specified TPDC send request queue
     * @param pdcid PDC identifier
     * @param req Request
     * @return Whether addition was successful
     */
    bool pushTxRequest(uint16_t pdcid, const PDS_PDC_req& req) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info || process_info->state.load() != RUNNING) {
            return false;
        }
        
        // Use instance member queue
        process_info->tpdc_instance->tx_req_q.push(req);
        process_info->last_activity = std::chrono::steady_clock::now();
        return true;
    }

    /**
     * @brief Add response to specified TPDC send response queue
     * @param pdcid PDC identifier
     * @param rsp Response
     * @return Whether addition was successful
     */
    bool pushTxResponse(uint16_t pdcid, const SES_PDC_rsp& rsp) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info || process_info->state.load() != RUNNING) {
            return false;
        }
        
        // Use instance member queue
        process_info->tpdc_instance->tx_rsp_q.push(rsp);
        process_info->last_activity = std::chrono::steady_clock::now();
        return true;
    }

    /**
     * @brief Get packet from specified TPDC send queue
     * @param pdcid PDC identifier
     * @param pkt Output data packet
     * @return Whether retrieval was successful
     */
    bool popTxPacket(uint16_t pdcid, PDStoNET_pkt& pkt) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info || process_info->tpdc_instance->tx_pkt_q.empty()) {
            return false;
        }
        
        // Use instance member queue
        pkt = process_info->tpdc_instance->tx_pkt_q.front();
        process_info->tpdc_instance->tx_pkt_q.pop();
        return true;
    }


    /**
     * @brief Get request from specified TPDC SES request queue
     * @param pdcid PDC identifier
     * @param req Output request
     * @return Whether retrieval was successful
     */
    bool popSESRequest(uint16_t pdcid, PDC_SES_req& req) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info || process_info->tpdc_instance->rx_req_pkt_q.empty()) {
            return false;
        }
        
        // Use instance member queue
        req = process_info->tpdc_instance->rx_req_pkt_q.front();
        process_info->tpdc_instance->rx_req_pkt_q.pop();
        return true;
    }

    /**
     * @brief Get response from specified TPDC SES response queue
     * @param pdcid PDC identifier
     * @param rsp Output response
     * @return Whether retrieval was successful
     */
    bool popSESResponse(uint16_t pdcid, PDC_SES_rsp& rsp) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info || process_info->tpdc_instance->rx_rsp_pkt_q.empty()) {
            return false;
        }
        
        // Use instance member queue
        rsp = process_info->tpdc_instance->rx_rsp_pkt_q.front();
        process_info->tpdc_instance->rx_rsp_pkt_q.pop();
        return true;
    }

    // ==================== Statistics and Monitoring Interface ====================

    /**
     * @brief Get active process count
     * @return Active process count
     */
    size_t getActiveProcessCount() {
        std::lock_guard<std::mutex> lock(manager_mutex);
        return std::count_if(tpdc_processes.begin(), tpdc_processes.end(),
            [](const auto& pair) {
                return pair.second->state.load() == RUNNING;
            });
    }

    /**
     * @brief Get status information of all processes
     * @return Process state mapping
     */
    std::unordered_map<uint16_t, ProcessState> 
    getAllProcessStates() {
        std::lock_guard<std::mutex> lock(manager_mutex);
        std::unordered_map<uint16_t, ProcessState> states;
        
        for (const auto& [pdcid, process_info] : tpdc_processes) {
            states[pdcid] = process_info->state.load();
        }
        
        return states;
    }

    /**
     * @brief Get queue status of specified process
     * @param pdcid PDC identifier
     * @return Queue status information
     */
    struct QueueStatus {
        size_t rx_pkt_count;
        size_t tx_req_count;
        size_t tx_rsp_count;
        size_t tx_pkt_count;
        size_t rx_req_count;
        size_t rx_rsp_count;
    };
    QueueStatus getQueueStatus(uint16_t pdcid) {
        QueueStatus status = {0, 0, 0, 0, 0, 0};
        
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info) {
            return status;
        }
        
        // Use instance member queue to get queue status - Note: queue size retrieval here is not thread-safe, for monitoring only
        status.rx_pkt_count = process_info->tpdc_instance->rx_pkt_q.size();
        status.tx_req_count = process_info->tpdc_instance->tx_req_q.size();
        status.tx_rsp_count = process_info->tpdc_instance->tx_rsp_q.size();
        status.tx_pkt_count = process_info->tpdc_instance->tx_pkt_q.size();
        status.rx_req_count = process_info->tpdc_instance->rx_req_pkt_q.size();
        status.rx_rsp_count = process_info->tpdc_instance->rx_rsp_pkt_q.size();
        
        return status;
    }

    /**
     * @brief Get status of specific TPDC
     * @param pdcid PDC identifier
     * @param state Output state
     * @return Whether retrieval was successful
     */
    pdc_state getPDCState(uint16_t pdcid) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info) {
            return pdc_state::CLOSED;
        }
        return process_info->tpdc_instance->state;
    }

    /**
     * @brief Check if TPDC can be closed using built-in PDC method
     * @param pdcid PDC identifier
     * @return Whether it can be closed
     */
    bool canTPDCCloseInternal(uint16_t pdcid) {
        auto* process_info = getProcessInfo(pdcid);
        if (!process_info) {
            return false;
        }
        
        auto* tpdc = process_info->tpdc_instance.get();
        if (!tpdc) {
            return false;
        }
        
        return tpdc->canSafelyClose();
    }

    //************************** Command Interface *************************** //

private:
    /**
     * @brief TPDC process main loop
     * @param process_info Process information
     */
    void tpdcProcessLoop(TPDC_ProcessInfo* process_info) {
        LOG_DEBUG(__FUNCTION__, "TPDC process started running, PDCID: " + std::to_string(process_info->pdcid));
        
        while (!process_info->should_stop.load()) {
            // Check if paused
            {
                std::unique_lock<std::mutex> lock(process_info->process_mutex);
                process_info->process_cv.wait(lock, [process_info] {
                    return process_info->state.load() != PAUSED || process_info->should_stop.load();
                });
            }
            
            if (process_info->should_stop.load()) {
                break;
            }
            
            // Execute TPDC main processing logic
            try {
                process_info->tpdc_instance->openChk();
                process_info->last_activity = std::chrono::steady_clock::now();
            } catch (const std::exception& e) {
                std::cerr << "TPDC process exception, PDCID: " << process_info->pdcid 
                        << ", Error: " << e.what() << std::endl;
            }
            
            // Brief sleep to avoid high CPU usage
            std::this_thread::sleep_for(OPENCHK_INTERVAL);
            //LOG_DEBUG(__FUNCTION__, "TPDC process main loop executed once, PDCID: " + std::to_string(process_info->pdcid));
        }
        
        process_info->state.store(STOPPED);
        LOG_DEBUG(__FUNCTION__, "TPDC process stopped, PDCID: " + std::to_string(process_info->pdcid));
    }

    /**
     * @brief Monitoring thread main loop
     */
    void monitorLoop() {
        LOG_DEBUG(__FUNCTION__, "Monitoring thread started");
        
        while (manager_running.load()) {
            std::this_thread::sleep_for(MONITOR_INTERVAL);
            
            if (!manager_running.load()) {
                break;
            }
            
            // Check process health status
            std::vector<uint16_t> unhealthy_processes;
            {
                std::lock_guard<std::mutex> lock(manager_mutex);
                for (const auto& [pdcid, process_info] : tpdc_processes) {
                    if (!checkProcessHealth(process_info.get())) {
                        unhealthy_processes.push_back(pdcid);
                    }
                }
            }
            
            // Handle unhealthy processes
            for (uint16_t pdcid : unhealthy_processes) {
                LOG_WARN(__FUNCTION__, "Unhealthy process detected, PDCID: " + std::to_string(pdcid));
                // Can choose to restart or stop process
            }
            
            // Clean up stopped processes
            cleanupStoppedProcesses();
            
            // Output statistics
            LOG_DEBUG(__FUNCTION__, "Active process count: " + std::to_string(getActiveProcessCount()));
        }
        
        LOG_DEBUG(__FUNCTION__, "Monitoring thread stopped");
    }

    /**
     * @brief Check process health status
     * @param process_info Process information
     * @return Whether process is healthy
     */
    bool checkProcessHealth(TPDC_ProcessInfo* process_info) {
        if (!process_info) {
            LOG_ERROR(__FUNCTION__, "Process health check failed, process info is null, PDCID: " + std::to_string(process_info->pdcid));
            return false;
        }
        
        // Check process status
        auto state = process_info->state.load();
        if (state == STOPPED) {
            LOG_WARN(__FUNCTION__, "Process has stopped, PDCID: " + std::to_string(process_info->pdcid));
            return false;
        }
        
        // Check for long inactivity
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - process_info->last_activity);
        if (duration > IDLE_TIMEOUT) {
            LOG_WARN(__FUNCTION__, "Process activity timeout, PDCID: " + std::to_string(process_info->pdcid));
            return false;
        }
        
        return true;
    }

    /**
     * @brief Clean up stopped processes
     */
    void cleanupStoppedProcesses() {
        std::lock_guard<std::mutex> lock(manager_mutex);
        for (auto it = tpdc_processes.begin(); it != tpdc_processes.end(); ) {
            if (it->second->state.load() == STOPPED) {
                LOG_DEBUG(__FUNCTION__, "Cleaning up stopped process, PDCID: " + std::to_string(it->first));
                it = tpdc_processes.erase(it);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Get process information (thread-safe)
     * @param pdcid PDC identifier
     * @return Process information pointer, returns nullptr if not exists
     */
    TPDC_ProcessInfo* getProcessInfo(uint16_t pdcid) {
        std::lock_guard<std::mutex> lock(manager_mutex);
        auto it = tpdc_processes.find(pdcid);
        if (it != tpdc_processes.end()) {
            return it->second.get();
        }
        return nullptr;
    }
};

#endif // TPDC_PROCESS_MANAGER_HPP