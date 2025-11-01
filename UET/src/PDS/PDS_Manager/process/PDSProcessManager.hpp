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
 * @file             PDSProcessManager.hpp
 * @brief            PDSProcessManager.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * PDSProcessManager.hpp
 */




#ifndef PDS_PROCESS_MANAGER_HPP
#define PDS_PROCESS_MANAGER_HPP

#include "../../PDS.hpp"
#include "../../PDS_Manager/PDSManager.hpp"
#include "../../PDC/process/ThreadSafeQueue.hpp"

#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <memory>

/**
 * @class PDSProcessManager
 * @brief PDS process manager class
 *
 * Manages a single PDS instance, running in an independent thread,
 * interacting with external systems through thread-safe queue mechanisms
 */
class PDSProcessManager
{
public:
    // Process state enumeration
    enum ProcessState
    {
        STOPPED, // Stopped
        RUNNING, // Running
        PAUSED,  // Paused
        STOPPING // Stopping
    };
    struct PDS_ProcessInfo
    {
        std::unique_ptr<PDS_Manager> pds_instance;           // PDS instance
        std::unique_ptr<std::thread> process_thread;         // Processing thread
        std::atomic<ProcessState> state;                     // Process state
        std::atomic<bool> should_stop;                       // Stop flag
        std::mutex process_mutex;                            // Process mutex
        std::condition_variable process_cv;                  // Condition variable
        std::chrono::steady_clock::time_point last_activity; // Last activity time

        PDS_ProcessInfo() : pds_instance(std::make_unique<PDS_Manager>()),
                            state(STOPPED),
                            should_stop(false),
                            last_activity(std::chrono::steady_clock::now()) {}
    };
    // Public queue references (for inter-module communication)
    ThreadSafeQueue<PDStoNET_pkt> *pds_to_net_queue = nullptr;
    ThreadSafeQueue<SES_PDS_req> *ses_to_pds_req_queue = nullptr;
    ThreadSafeQueue<SES_PDS_rsp> *ses_to_pds_rsp_queue = nullptr;
    ThreadSafeQueue<PDStoNET_pkt> *net_to_pds_pkt_queue = nullptr;
    ThreadSafeQueue<PDS_SES_error> *pds_error_queue = nullptr;

    /**
     * @brief Set public queue references
     * @param pds_to_net PDStoNet queue
     * @param ses_to_pds_req SES to PDS request queue
     * @param ses_to_pds_rsp SES to PDS response queue
     * @param net_to_pds_pkt Network to PDS packet queue
     * @param pds_error_queue PDS error queue
     */
    void setPublicQueues(
        ThreadSafeQueue<PDStoNET_pkt> *pds_to_net,
        ThreadSafeQueue<SES_PDS_req> *ses_to_pds_req,
        ThreadSafeQueue<SES_PDS_rsp> *ses_to_pds_rsp,
        ThreadSafeQueue<PDStoNET_pkt> *net_to_pds_pkt,
        ThreadSafeQueue<PDS_SES_error> *pds_error)
    {
        pds_to_net_queue = pds_to_net;
        ses_to_pds_req_queue = ses_to_pds_req;
        ses_to_pds_rsp_queue = ses_to_pds_rsp;
        net_to_pds_pkt_queue = net_to_pds_pkt;
        pds_error_queue = pds_error;
        LOG_DEBUG(__FUNCTION__, "PDS process manager public queue references set");
    }

private:
    // PDS process information structure

    // Manager member variables
    std::unique_ptr<PDS_ProcessInfo> pds_process_info; // PDS process information
    std::mutex manager_mutex;                          // Manager mutex
    std::atomic<bool> manager_running;                 // Manager running status
    std::unique_ptr<std::thread> monitor_thread;       // Monitoring thread

    // Configuration parameters
    static constexpr std::chrono::milliseconds MAINCHK_INTERVAL{1}; // mainChk call interval
    static constexpr std::chrono::seconds MONITOR_INTERVAL{5};      // Monitoring interval
    static constexpr std::chrono::seconds IDLE_TIMEOUT{300};        // Idle timeout

public:
    /**
     * @brief Constructor
     */
    PDSProcessManager() : manager_running(false)
    {
        LOG_DEBUG(__FUNCTION__, "PDS process manager initialized");
    }

    /**
     * @brief Destructor
     */
    ~PDSProcessManager()
    {
        LOG_DEBUG(__FUNCTION__, "PDS进程管理器析构开始");
        stop();
        LOG_DEBUG(__FUNCTION__, "PDS process manager destroyed");
    }

    /**
     * @brief Initialize PDS process manager
     * @return Whether initialization was successful
     */
    bool initialize()
    {
        LOG_DEBUG(__FUNCTION__, "Initializing PDS process manager");
        
        /*
        // 创建默认队列
        if (!pds_to_net_queue) {
            pds_to_net_queue = new ThreadSafeQueue<PDStoNET_pkt>(1024);
            LOG_DEBUG(__FUNCTION__, "Creating PDStoNet queue");
        }
        
        if (!ses_to_pds_req_queue) {
            ses_to_pds_req_queue = new ThreadSafeQueue<SES_PDS_req>(512);
            LOG_DEBUG(__FUNCTION__, "Creating SES to PDS request queue");
        }
        
        if (!ses_to_pds_rsp_queue) {
            ses_to_pds_rsp_queue = new ThreadSafeQueue<SES_PDS_rsp>(512);
            LOG_DEBUG(__FUNCTION__, "Creating SES to PDS response queue");
        }
        
        if (!net_to_pds_pkt_queue) {
            net_to_pds_pkt_queue = new ThreadSafeQueue<PDStoNET_pkt>(1024);
            LOG_DEBUG(__FUNCTION__, "Creating network to PDS packet queue");
        }
        
        if (!pds_error_queue) {
            pds_error_queue = new ThreadSafeQueue<PDS_SES_error>(256);
            LOG_DEBUG(__FUNCTION__, "Creating PDS error queue");
        }
        */
        return true;
    }

    /**
     * @brief Start manager
     * @return Whether startup was successful
     */
    bool start()
    {
        std::lock_guard<std::mutex> lock(manager_mutex);

        if (manager_running.load())
        {
            LOG_ERROR(__FUNCTION__, "Manager is already running");
            return false;
        }

        // Initialize queues (if not set)
        if (!initialize())
        {
            LOG_ERROR(__FUNCTION__, "PDS process manager initialization failed");
            return false;
        }

        // Create PDS process information
        pds_process_info = std::make_unique<PDS_ProcessInfo>();

        // Initialize PDS instance
        if (!pds_process_info->pds_instance->initPDSM())
        {
            LOG_ERROR(__FUNCTION__, "Failed to initialize PDS instance");
            return false;
        }

        manager_running.store(true);
        pds_process_info->state.store(RUNNING);
        // Start processing thread
        pds_process_info->process_thread = std::make_unique<std::thread>(
            &PDSProcessManager::pdsProcessLoop, this);

        // Start monitoring thread
        monitor_thread = std::make_unique<std::thread>(&PDSProcessManager::monitorLoop, this);

        LOG_DEBUG(__FUNCTION__, "PDS process manager started");
        // Get PDS running status
        ProcessState pds_state = pds_process_info->state.load();
        LOG_INFO(__FUNCTION__, "PDS process state: " + std::to_string(static_cast<int>(pds_state)));

        return true;
    }

    /**
     * @brief Stop manager
     */
    void stop()
    {
        LOG_DEBUG(__FUNCTION__, "Stopping PDS process manager...");

        manager_running.store(false);

        // Stop PDS process
        if (pds_process_info && pds_process_info->state.load() != STOPPED)
        {
            pds_process_info->should_stop.store(true);
            pds_process_info->process_cv.notify_all();

            if (pds_process_info->process_thread && pds_process_info->process_thread->joinable())
            {
                pds_process_info->process_thread->join();
            }
        }

        // Stop monitoring thread
        if (monitor_thread && monitor_thread->joinable())
        {
            monitor_thread->join();
        }

        LOG_DEBUG(__FUNCTION__, "PDS process manager stopped");
    }

    /**
     * @brief Pause PDS process
     * @return Whether pause was successful
     */
    bool pausePDSProcess()
    {
        if (!pds_process_info)
        {
            return false;
        }

        std::lock_guard<std::mutex> lock(pds_process_info->process_mutex);
        if (pds_process_info->state.load() == RUNNING)
        {
            pds_process_info->state.store(PAUSED);
            LOG_DEBUG(__FUNCTION__, "Pausing PDS process");
            return true;
        }
        return false;
    }

    /**
     * @brief Resume PDS process
     * @return Whether resume was successful
     */
    bool resumePDSProcess()
    {
        if (!pds_process_info)
        {
            return false;
        }

        std::lock_guard<std::mutex> lock(pds_process_info->process_mutex);
        if (pds_process_info->state.load() == PAUSED)
        {
            pds_process_info->state.store(RUNNING);
            pds_process_info->process_cv.notify_all();
            LOG_DEBUG(__FUNCTION__, "Resuming PDS process");
            return true;
        }
        return false;
    }

    /**
     * @brief Get PDS process state
     * @return Process state
     */
    ProcessState getProcessState()
    {
        return pds_process_info ? pds_process_info->state.load() : STOPPED;
    }

    // ==================== 队列交互接口 ====================

    /**
     * @brief Add request to PDS SES request queue
     * @param req Request
     * @return Whether addition was successful
     */
    bool pushSESRequest(const SES_PDS_req &req)
    {
        if (!pds_process_info || pds_process_info->state.load() != RUNNING)
        {
            return false;
        }

        // Thread-safely add to request queue
        pds_process_info->pds_instance->SES_tx_req_q.push(req);
        pds_process_info->last_activity = std::chrono::steady_clock::now();
        return true;
    }

    /**
     * @brief Add response to PDS SES response queue
     * @param rsp Response
     * @return Whether addition was successful
     */
    bool pushSESResponse(const SES_PDS_rsp &rsp)
    {
        if (!pds_process_info || pds_process_info->state.load() != RUNNING)
        {
            return false;
        }

        // Thread-safely add to response queue
        pds_process_info->pds_instance->SES_tx_rsp_q.push(rsp);
        pds_process_info->last_activity = std::chrono::steady_clock::now();
        return true;
    }

    /**
     * @brief Add packet to PDS network layer receive queue
     * @param pkt Packet
     * @return Whether addition was successful
     */
    bool pushNetworkPacket(const PDStoNET_pkt &pkt)
    {
        if (!pds_process_info || pds_process_info->state.load() != RUNNING)
        {
            return false;
        }

        // Thread-safely add to network layer receive queue
        pds_process_info->pds_instance->Net_rx_pkt_q.push(pkt);
        pds_process_info->last_activity = std::chrono::steady_clock::now();
        return true;
    }

    /**
     * @brief Get request from PDS eager request queue
     * @param req Output request
     * @return Whether retrieval was successful
     */
    bool popEagerRequest(SES_PDS_eager &req)
    {
        if (!pds_process_info || pds_process_info->pds_instance->SES_eager_req_q.empty())
        {
            return false;
        }

        req = pds_process_info->pds_instance->SES_eager_req_q.front();
        pds_process_info->pds_instance->SES_eager_req_q.pop();
        return true;
    }

    /**
     * @brief Get error event from PDS error queue
     * @param error Output error event
     * @return Whether retrieval was successful
     */
    bool popErrorEvent(PDS_SES_error &error)
    {
        if (!pds_process_info || pds_process_info->pds_instance->PDS_error_q.empty())
        {
            return false;
        }

        error = pds_process_info->pds_instance->PDS_error_q.front();
        pds_process_info->pds_instance->PDS_error_q.pop();
        return true;
    }

    /**
     * @brief Get network layer packet from PDS public queue
     * @param pkt Output packet
     * @return Whether retrieval was successful
     */
    bool popNetworkPacket(PDStoNET_pkt &pkt)
    {
        if (!pds_process_info || pds_process_info->pds_instance->PDStoNet.empty())
        {
            return false;
        }

        return pds_process_info->pds_instance->PDStoNet.pop(pkt);
    }

    /**
     * @brief Get SES request from PDS public queue
     * @param req Output request
     * @return Whether retrieval was successful
     */
    bool popSESRequest(PDC_SES_req &req)
    {
        if (!pds_process_info || pds_process_info->pds_instance->PDCtoSES_req.empty())
        {
            return false;
        }

        return pds_process_info->pds_instance->PDCtoSES_req.pop(req);
    }

    /**
     * @brief Get SES response from PDS public queue
     * @param rsp Output response
     * @return Whether retrieval was successful
     */
    bool popSESResponse(PDC_SES_rsp &rsp)
    {
        if (!pds_process_info || pds_process_info->pds_instance->PDCtoSES_rsp.empty())
        {
            return false;
        }

        return pds_process_info->pds_instance->PDCtoSES_rsp.pop(rsp);
    }

    // ==================== 统计和监控接口 ====================

    /**
     * @brief Get PDS status information
     * @return PDS status information
     */
    struct PDSStatus
    {
        int open_cnt;       // 当前打开的PDC数量
        int pend_cnt;       // 等待处理的任务数量
        int closing_cnt;    // 正在关闭的PDC数量
        int event_cnt;      // 事件计数器
        ProcessState state; // Process state
    };

    PDSStatus getPDSStatus()
    {
        PDSStatus status = {0, 0, 0, 0, RUNNING};

        if (pds_process_info)
        {
            status.open_cnt = pds_process_info->pds_instance->open_cnt;
            status.pend_cnt = pds_process_info->pds_instance->pend_cnt;
            status.closing_cnt = pds_process_info->pds_instance->closing_cnt;
            status.event_cnt = pds_process_info->pds_instance->event_cnt;
            status.state = pds_process_info->state.load();
        }

        return status;
    }

    /**
     * @brief Get queue status information
     * @return Queue status information
     */
    struct QueueStatus
    {
        size_t ses_req_count;
        size_t ses_rsp_count;
        size_t net_pkt_count;
        size_t eager_req_count;
        size_t error_count;
        size_t pdc_to_net_count;
        size_t pdc_to_ses_req_count;
        size_t pdc_to_ses_rsp_count;
    };

    QueueStatus getQueueStatus()
    {
        QueueStatus status = {0, 0, 0, 0, 0, 0, 0, 0};

        if (pds_process_info)
        {
            status.ses_req_count = pds_process_info->pds_instance->SES_tx_req_q.size();
            status.ses_rsp_count = pds_process_info->pds_instance->SES_tx_rsp_q.size();
            status.net_pkt_count = pds_process_info->pds_instance->Net_rx_pkt_q.size();
            status.eager_req_count = pds_process_info->pds_instance->SES_eager_req_q.size();
            status.error_count = pds_process_info->pds_instance->PDS_error_q.size();
            status.pdc_to_net_count = pds_process_info->pds_instance->PDStoNet.size();
            status.pdc_to_ses_req_count = pds_process_info->pds_instance->PDCtoSES_req.size();
            status.pdc_to_ses_rsp_count = pds_process_info->pds_instance->PDCtoSES_rsp.size();
        }

        return status;
    }

private:
    /**
     * @brief PDS process main loop
     */
    void pdsProcessLoop()
    {
        LOG_DEBUG(__FUNCTION__, "PDS process started running");

        while (!pds_process_info->should_stop.load())
        {
            // Check if paused
            {
                std::unique_lock<std::mutex> lock(pds_process_info->process_mutex);
                pds_process_info->process_cv.wait(lock, [this]
                                                  { return pds_process_info->state.load() != PAUSED || pds_process_info->should_stop.load(); });
            }

            if (pds_process_info->should_stop.load())
            {
                break;
            }

            // Execute PDS main processing logic
            try
            {
                pds_process_info->pds_instance->mainChk();
                pds_process_info->last_activity = std::chrono::steady_clock::now();
                pds_process_info->state.store(RUNNING);
            }
            catch (const std::exception &e)
            {
                LOG_ERROR(__FUNCTION__, "PDS process exception, error: " + std::string(e.what()));
            }

            // Brief sleep to avoid high CPU usage
            std::this_thread::sleep_for(MAINCHK_INTERVAL);
            LOG_DEBUG(__FUNCTION__, "PDS process main loop executed once");
        }

        pds_process_info->state.store(STOPPED);
        LOG_DEBUG(__FUNCTION__, "PDS process stopped");
    }

    /**
     * @brief Monitor thread main loop
     */
    void monitorLoop()
    {
        LOG_DEBUG(__FUNCTION__, "Monitoring thread started");

        while (manager_running.load())
        {
            std::this_thread::sleep_for(MONITOR_INTERVAL);

            if (!manager_running.load())
            {
                break;
            }

            // Check process health status
            if (pds_process_info && !checkProcessHealth(pds_process_info.get()))
            {
                LOG_WARN(__FUNCTION__, "Unhealthy PDS process detected");
                // 可以选择重启或停止进程
            }

            // Output statistics
            LOG_DEBUG(__FUNCTION__, "PDS status: " + std::to_string(static_cast<int>(getProcessState())));
            LOG_DEBUG(__FUNCTION__, "Active PDC count: " + std::to_string(getPDSStatus().open_cnt));
            LOG_DEBUG(__FUNCTION__, "Pending task count: " + std::to_string(getPDSStatus().pend_cnt));
        }

        LOG_DEBUG(__FUNCTION__, "Monitoring thread stopped");
    }

    /**
     * @brief Check process health status
     * @param process_info Process information
     * @return Whether process is healthy
     */
    bool checkProcessHealth(PDS_ProcessInfo *process_info)
    {
        if (!process_info)
        {
            return false;
        }

        // Check process status
        auto state = process_info->state.load();
        if (state == STOPPED)
        {
            return false;
        }

        // Check for long inactivity
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - process_info->last_activity);
        if (duration > IDLE_TIMEOUT)
        {
            LOG_WARN(__FUNCTION__, "PDS process activity timeout");
            return false;
        }

        return true;
    }
};

#endif // PDS_PROCESS_MANAGER_HPP