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
#include "../../../Runtime/Runtime.hpp"
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
        uint16_t rto;           ///< Legacy diagnostic/API view: duration rounded up to milliseconds.
        UET::Runtime::Time duration_ns=0; ///< Canonical duration; protocol timing never uses the rounded view.
        UET::Runtime::Time start_time_ns=0; ///< Injected-clock start, meaningful when services are present.
        uint16_t retry_count;    ///< Retry count
        std::chrono::steady_clock::time_point start_time; ///< Timer start time
        bool active;            ///< Whether timer is active
    };

    using TimeoutCallback = std::function<void(uint32_t psn)>;

    /**
     * @brief Constructor
     * @param timeout_callback Timeout callback function, parameter is timeout PSN
     */
    explicit RTOTimer(TimeoutCallback timeout_callback = nullptr,
                      UET::Runtime::Services* services = nullptr);

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
    // Nanosecond API used by the protocol. Zero is a valid immediate timeout;
    // the legacy millisecond API retains its old zero-rejection behavior.
    bool startTimerNanoseconds(uint32_t psn,uint64_t initial_ns,uint16_t timeout_retries=0);

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
    bool updateNanoseconds(uint32_t psn,uint64_t duration_ns);

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
    UET::Runtime::Services* services_ = nullptr;
    std::map<uint32_t, UET::Runtime::TimerId> event_ids_;
    std::map<uint32_t, uint64_t> event_versions_;
    uint64_t revision_ = 0;
    std::shared_ptr<int> lifetime_ = std::make_shared<int>(0);
    bool startDuration(uint32_t psn,uint64_t duration_ns,uint16_t timeout_retries);
    void scheduleVirtual(uint32_t psn, uint64_t duration_ns);
    /**
     * @brief Timer monitoring thread function
     */
    void monitorThread();

    mutable std::mutex mutex_;                          ///< Thread-safe mutex
    std::map<uint32_t, TimerItem> timers_;              ///< Timer map
    TimeoutCallback timeout_callback_;                 ///< Timeout callback function
    std::atomic<bool> running_{false};                 ///< Timer thread running flag
    std::thread monitor_thread_;                       ///< Monitoring thread
    std::condition_variable cv_;                       ///< Condition variable for thread synchronization
};

#endif // RTO_TIMER_HPP
