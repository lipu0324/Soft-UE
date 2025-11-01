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
 * @file             RTOTimer.cpp
 * @brief            RTOTimer.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This file implements the RTO (Retransmission Timeout) timer with exponential backoff support.
 */




#include "RTOTimer.hpp"
#include <iostream>
#include <algorithm>

/**
 * @brief Constructor
 * @param timeout_callback Timeout callback function
 */
RTOTimer::RTOTimer(TimeoutCallback timeout_callback)
    : timeout_callback_(std::move(timeout_callback))
    , running_(false)
{
    
    running_ = true;
    monitor_thread_ = std::thread(&RTOTimer::monitorThread, this);
}

/**
 * @brief Destructor
 */
RTOTimer::~RTOTimer()
{
    stop();
}

/**
 * @brief Start timer
 * @param psn Packet sequence number
 * @param base_rto Base RTO time
 * @param retry_count Current retry count
 * @return Whether startup was successful
 */
bool RTOTimer::startTimer(uint32_t psn, uint16_t base_rto, uint16_t retry_count)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Calculate RTO after exponential backoff
    uint16_t calculated_rto = calculateExponentialBackoff(base_rto, retry_count);
    
    // Create or update timer item
    TimerItem item;
    item.psn = psn;
    item.rto = calculated_rto;
    item.retry_count = retry_count;
    item.start_time = std::chrono::steady_clock::now();
    item.active = true;
    
    timers_[psn] = item;
    
    LOG_DEBUG("RTOTimer::startTimer", 
              "Start timer - PSN: " + std::to_string(psn) + 
              ", RTO: " + std::to_string(calculated_rto) + "ms" +
              ", retry count: " + std::to_string(retry_count));
    
    // Notify monitoring thread
    cv_.notify_one();
    return true;
}

/**
 * @brief Stop and remove timer
 * @param psn Packet sequence number
 * @return Whether removal was successful
 */
bool RTOTimer::stopTimer(uint32_t psn)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = timers_.find(psn);
    if (it != timers_.end()) {
        it->second.active = false;
        timers_.erase(it);
        
        LOG_DEBUG("RTOTimer::stopTimer", 
                  "Stop timer - PSN: " + std::to_string(psn));
        return true;
    }
    
    LOG_WARN("RTOTimer::stopTimer", 
             "Timer not found - PSN: " + std::to_string(psn));
    return false;
}

/**
 * @brief Update timer RTO time
 * @param psn Packet sequence number
 * @param new_rto New RTO time
 * @return Whether update was successful
 */
bool RTOTimer::updateRTO(uint32_t psn, uint16_t new_rto)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = timers_.find(psn);
    if (it != timers_.end() && it->second.active) {
        it->second.rto = new_rto;
        it->second.start_time = std::chrono::steady_clock::now();
        
        LOG_DEBUG("RTOTimer::updateRTO", 
                  "Update RTO - PSN: " + std::to_string(psn) + 
                  ", new RTO: " + std::to_string(new_rto) + "ms");
        return true;
    }
    
    return false;
}

/**
 * @brief Get timer status
 * @param psn Packet sequence number
 * @return Timer item
 */
RTOTimer::TimerItem RTOTimer::getTimerInfo(uint32_t psn) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = timers_.find(psn);
    if (it != timers_.end()) {
        return it->second;
    }
    
    return TimerItem{};
}

/**
 * @brief Check if timer is active
 * @param psn Packet sequence number
 * @return Whether timer is active
 */
bool RTOTimer::isTimerActive(uint32_t psn) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = timers_.find(psn);
    return it != timers_.end() && it->second.active;
}

/**
 * @brief Get active timer count
 * @return Active timer count
 */
size_t RTOTimer::getActiveTimerCount() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = 0;
    for (const auto& pair : timers_) {
        if (pair.second.active) {
            count++;
        }
    }
    return count;
}

/**
 * @brief Clear all timers
 */
void RTOTimer::clearAllTimers()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    LOG_INFO("RTOTimer::clearAllTimers", 
             "Clear all timers - total count: " + std::to_string(timers_.size()));
    timers_.clear();
}

/**
 * @brief Set timeout callback function
 * @param callback Callback function
 */
void RTOTimer::setTimeoutCallback(TimeoutCallback callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    timeout_callback_ = std::move(callback);
}

/**
 * @brief Stop timer thread
 */
void RTOTimer::stop()
{
    if (running_) {
        running_ = false;
        cv_.notify_all();
        
        if (monitor_thread_.joinable()) {
            monitor_thread_.join();
        }
    }
}

/**
 * @brief Timer monitoring thread function
 */
void RTOTimer::monitorThread()
{
    LOG_INFO("RTOTimer::monitorThread", "Monitoring thread started");
    
    while (running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        if (timers_.empty()) {
            // No timers, wait for notification
            cv_.wait(lock, [this] { 
                return !running_ || !timers_.empty(); 
            });
            continue;
        }
        
        // Find earliest expiring timer
        auto earliest_it = timers_.end();
        auto earliest_time = std::chrono::steady_clock::time_point::max();
        
        for (auto it = timers_.begin(); it != timers_.end(); ++it) {
            if (it->second.active) {
                auto expire_time = it->second.start_time + 
                                 std::chrono::milliseconds(it->second.rto);
                if (expire_time < earliest_time) {
                    earliest_time = expire_time;
                    earliest_it = it;
                }
            }
        }
        
        if (earliest_it == timers_.end()) {
            // No active timers, wait for notification
            cv_.wait(lock);
            continue;
        }
        
        // Calculate wait time
        auto now = std::chrono::steady_clock::now();
        if (earliest_time > now) {
            // Wait until timeout or notification
            cv_.wait_until(lock, earliest_time, [this] { 
                return !running_; 
            });
            continue;
        }
        
        // Handle timeout
        uint32_t expired_psn = earliest_it->first;
        TimerItem expired_item = earliest_it->second;
        
        // Remove expired timer
        timers_.erase(earliest_it);
        
        lock.unlock();
        
        // Execute timeout callback
        if (timeout_callback_) {
            LOG_WARN("RTOTimer::monitorThread", 
                     "Timer timeout - PSN: " + std::to_string(expired_psn) +
                     ", RTO: " + std::to_string(expired_item.rto) + "ms");
            
            timeout_callback_(expired_psn);
        }
    }
    
    LOG_INFO("RTOTimer::monitorThread", "Monitoring thread stopped");
}

/**
 * @brief Calculate RTO time after exponential backoff
 * @param base_rto Base RTO
 * @param retry_count Retry count
 * @return Calculated RTO
 */
uint16_t RTOTimer::calculateExponentialBackoff(uint16_t base_rto, uint16_t retry_count) const
{
    if (retry_count == 0) {
        return base_rto;
    }
    
    // Exponential backoff: RTO = base_rto * (2^retry_count)
    // Limit maximum RTO to 10 seconds
    uint32_t calculated_rto = base_rto * (1 << retry_count);
    return static_cast<uint16_t>(std::min(calculated_rto, 10000u));
}