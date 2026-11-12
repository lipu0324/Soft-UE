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

namespace {
uint16_t diagnostic_milliseconds(uint64_t duration_ns) {
    const auto rounded=duration_ns/UET::Runtime::kMillisecond+(duration_ns%UET::Runtime::kMillisecond!=0);
    return static_cast<uint16_t>(std::min<uint64_t>(UINT16_MAX,rounded));
}
}

/**
 * @brief Constructor
 * @param timeout_callback Timeout callback function
 */
RTOTimer::RTOTimer(TimeoutCallback timeout_callback, UET::Runtime::Services* services)
    : services_(services)
    , timeout_callback_(std::move(timeout_callback))
    , running_(false)
{
    
    running_ = true;
    if (!services_) monitor_thread_ = std::thread(&RTOTimer::monitorThread, this);
}

/**
 * @brief Destructor
 */
RTOTimer::~RTOTimer()
{
    stop();
    lifetime_.reset();
}

void RTOTimer::scheduleVirtual(uint32_t psn, uint64_t duration_ns)
{
    const auto when = UET::Runtime::add_time(services_->clock.now(),duration_ns);
    auto old = event_ids_.find(psn);
    if (old != event_ids_.end()) services_->timers.cancel(old->second);
    const auto version = ++revision_;
    event_versions_[psn] = version;
    const std::weak_ptr<int> life = lifetime_;
    event_ids_[psn] = services_->timers.at(when, [this, life, psn, version] {
        if (life.expired()) return;
        TimeoutCallback callback;
        std::function<void()> wake;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto found = event_versions_.find(psn);
            if (!running_ || found == event_versions_.end() || found->second != version) return;
            timers_.erase(psn);
            event_ids_.erase(psn);
            event_versions_.erase(found);
            callback = timeout_callback_;
            wake = services_->wake;
        }
        if (callback) callback(psn);
        if (wake) wake();
    });
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
    if (!base_rto) return false;
    // Preserve the historical cap only at the explicitly millisecond-based
    // compatibility API. Standard PDS uses the exact nanosecond API below.
    const auto duration=UET::Runtime::retransmission_timeout_ns(uint64_t{base_rto}*UET::Runtime::kMillisecond,retry_count);
    return startDuration(psn,std::min<uint64_t>(10000000000ULL,duration),retry_count);
}

bool RTOTimer::startTimerNanoseconds(uint32_t psn,uint64_t initial_ns,uint16_t timeout_retries)
{
    return startDuration(psn,UET::Runtime::retransmission_timeout_ns(initial_ns,timeout_retries),timeout_retries);
}

bool RTOTimer::startDuration(uint32_t psn,uint64_t duration_ns,uint16_t timeout_retries)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_) return false;
    
    // Check before mutating an existing timer: an unrepresentable deadline
    // must leave its old valid event intact. No wall-clock read in virtual mode.
    const auto wall_start=services_?std::chrono::steady_clock::time_point{}:std::chrono::steady_clock::now();
    if (services_) UET::Runtime::add_time(services_->clock.now(),duration_ns);
    else if (duration_ns>static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::time_point::max()-wall_start).count()))
        throw std::overflow_error("wall-clock retransmission deadline overflow");
    
    // Create or update timer item
    TimerItem item;
    item.psn = psn;
    item.duration_ns=duration_ns;
    item.rto=diagnostic_milliseconds(duration_ns);
    item.retry_count = timeout_retries;
    item.start_time_ns=services_?services_->clock.now():0;
    item.start_time=wall_start;
    item.active = true;
    
    timers_[psn] = item;
    if (services_) scheduleVirtual(psn,duration_ns);
    
    LOG_DEBUG("RTOTimer::startTimer", 
              "Start timer - PSN: " + std::to_string(psn) + 
              ", RTO: " + std::to_string(duration_ns) + "ns" +
              ", timeout retry count: " + std::to_string(timeout_retries));
    
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
        if (services_) {
            auto event = event_ids_.find(psn);
            if (event != event_ids_.end()) { services_->timers.cancel(event->second); event_ids_.erase(event); }
            event_versions_.erase(psn);
        }
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
    if (!new_rto) return false;
    return updateNanoseconds(psn,uint64_t{new_rto}*UET::Runtime::kMillisecond);
}

bool RTOTimer::updateNanoseconds(uint32_t psn,uint64_t duration_ns)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_) return false;
    
    auto it = timers_.find(psn);
    if (it != timers_.end() && it->second.active) {
        const auto wall_start=services_?std::chrono::steady_clock::time_point{}:std::chrono::steady_clock::now();
        if (services_) UET::Runtime::add_time(services_->clock.now(),duration_ns);
        else if (duration_ns>static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::time_point::max()-wall_start).count()))
            throw std::overflow_error("wall-clock retransmission deadline overflow");
        it->second.duration_ns=duration_ns;
        it->second.rto=diagnostic_milliseconds(duration_ns);
        it->second.start_time_ns=services_?services_->clock.now():0;
        it->second.start_time=wall_start;
        if (services_) scheduleVirtual(psn,duration_ns);
        
        LOG_DEBUG("RTOTimer::updateRTO", 
                  "Update RTO - PSN: " + std::to_string(psn) + 
                  ", new RTO: " + std::to_string(duration_ns) + "ns");
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
    if (services_) {
        for (const auto& event : event_ids_) services_->timers.cancel(event.second);
        event_ids_.clear();
        event_versions_.clear();
    }
    
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
    clearAllTimers();
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
                                 std::chrono::nanoseconds(it->second.duration_ns);
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
