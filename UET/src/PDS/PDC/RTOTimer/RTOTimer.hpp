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
 * @file             RTOTimer.hpp
 * @brief            RTOTimer.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This header defines the RTO timer class for managing packet retransmission timeouts with exponential backoff.
 */


#ifndef RTO_TIMER_HPP
#define RTO_TIMER_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <queue>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "../../../logger/Logger.hpp"

/**
 * @class RTOTimer
 * @brief RTO timer class, responsible for managing PDC timeout and retransmission timing
 *
 * This class maintains independent timers for each sent packet, puts PSN into retransmission queue when timeout occurs
 */
class RTOTimer
{
public:
    /**
     * @brief Timer item structure
     */
    struct TimerItem
    {
        uint32_t psn;           ///< Packet sequence number
        uint16_t rto;           ///< Retransmission timeout time (ms)
        uint16_t retry_count;    ///< Retry count
        std::chrono::steady_clock::time_point start_time; ///< Timer start time
        bool active;            ///< Whether timer is active
    };

    using TimeoutCallback = std::function<void(uint32_t psn)>;

    /**
     * @brief Constructor
     * @param timeout_callback Timeout callback function, parameter is timeout PSN
     */
    explicit RTOTimer(TimeoutCallback timeout_callback = nullptr);

    /**
     * @brief Destructor
     */
    ~RTOTimer();

    /**
     * @brief Start timer
     * @param psn Packet sequence number
     * @param base_rto Base RTO time (ms)
     * @param retry_count Current retry count
     * @return Whether successfully started
     */
    bool startTimer(uint32_t psn, uint16_t base_rto, uint16_t retry_count = 0);

    /**
     * @brief Stop and remove timer
     * @param psn Packet sequence number
     * @return Whether successfully removed
     */
    bool stopTimer(uint32_t psn);

    /**
     * @brief Update timer's RTO time
     * @param psn Packet sequence number
     * @param new_rto New RTO time (ms)
     * @return Whether successfully updated
     */
    bool updateRTO(uint32_t psn, uint16_t new_rto);

    /**
     * @brief Get timer status
     * @param psn Packet sequence number
     * @return Timer item, returns empty item if not exists
     */
    TimerItem getTimerInfo(uint32_t psn) const;

    /**
     * @brief Check if timer is active
     * @param psn Packet sequence number
     * @return Whether active
     */
    bool isTimerActive(uint32_t psn) const;

    /**
     * @brief Get active timer count
     * @return Active timer count
     */
    size_t getActiveTimerCount() const;

    /**
     * @brief Clear all timers
     */
    void clearAllTimers();

    /**
     * @brief Set timeout callback function
     * @param callback Callback function
     */
    void setTimeoutCallback(TimeoutCallback callback);

    /**
     * @brief Stop timer thread
     */
    void stop();

private:
    /**
     * @brief Timer monitoring thread function
     */
    void monitorThread();

    /**
     * @brief Calculate RTO time after exponential backoff
     * @param base_rto Base RTO
     * @param retry_count Retry count
     * @return Calculated RTO
     */
    uint16_t calculateExponentialBackoff(uint16_t base_rto, uint16_t retry_count) const;

    mutable std::mutex mutex_;                          ///< Thread-safe mutex
    std::map<uint32_t, TimerItem> timers_;              ///< Timer map
    TimeoutCallback timeout_callback_;                 ///< Timeout callback function
    std::atomic<bool> running_{false};                 ///< Timer thread running flag
    std::thread monitor_thread_;                       ///< Monitoring thread
    std::condition_variable cv_;                       ///< Condition variable for thread synchronization
};

#endif // RTO_TIMER_HPP