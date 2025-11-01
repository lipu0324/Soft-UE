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
 * @file             ThreadSafeQueue.hpp
 * @brief            ThreadSafeQueue.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This header provides thread-safe queue and queue manager templates for concurrent programming.
 */


#ifndef THREAD_SAFE_QUEUE_HPP
#define THREAD_SAFE_QUEUE_HPP

#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <memory>
#include <unordered_map>

/**
 * @class ThreadSafeQueue
 * @brief Thread-safe queue template class
 * @tparam T Queue element type
 */
template<typename T>
class ThreadSafeQueue {
private:
    mutable std::mutex queue_mutex;         // Queue mutex
    std::queue<T> data_queue;               // Data queue
    std::condition_variable condition;      // Condition variable
    std::atomic<size_t> max_size;          // Maximum queue size
    std::atomic<bool> shutdown;            // Shutdown flag

public:
    /**
     * @brief Constructor
     * @param max_queue_size Maximum queue size, 0 means unlimited
     */
    explicit ThreadSafeQueue(size_t max_queue_size = 0) 
        : max_size(max_queue_size), shutdown(false) {}

    /**
     * @brief Destructor
     */
    ~ThreadSafeQueue() {
        shutdown_queue();
    }

    /**
     * @brief Disable copy constructor and assignment
     */
    ThreadSafeQueue(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    /**
     * @brief Add element to queue (non-blocking)
     * @param item Element to add
     * @return Whether addition was successful
     */
    bool push(const T& item) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        if (shutdown.load()) {
            return false;
        }
        
        // Check queue size limit
        if (max_size.load() > 0 && data_queue.size() >= max_size.load()) {
            return false; // Queue is full
        }
        
        data_queue.push(item);
        condition.notify_one();
        return true;
    }

    /**
     * @brief Add element to queue (move semantics)
     * @param item Element to add
     * @return Whether addition was successful
     */
    bool push(T&& item) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        if (shutdown.load()) {
            return false;
        }
        
        if (max_size.load() > 0 && data_queue.size() >= max_size.load()) {
            return false;
        }
        
        data_queue.push(std::move(item));
        condition.notify_one();
        return true;
    }

    /**
     * @brief Blocking add element to queue
     * @param item Element to add
     * @param timeout_ms Timeout in milliseconds, 0 means infinite wait
     * @return Whether addition was successful
     */
    bool push_blocking(const T& item, uint32_t timeout_ms = 0) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        
        if (shutdown.load()) {
            return false;
        }
        
        // Wait for queue to have space
        if (max_size.load() > 0) {
            auto wait_condition = [this] { 
                return data_queue.size() < max_size.load() || shutdown.load(); 
            };
            
            if (timeout_ms > 0) {
                if (!condition.wait_for(lock, std::chrono::milliseconds(timeout_ms), wait_condition)) {
                    return false; // Timeout
                }
            } else {
                condition.wait(lock, wait_condition);
            }
            
            if (shutdown.load()) {
                return false;
            }
        }
        
        data_queue.push(item);
        condition.notify_one();
        return true;
    }

    /**
     * @brief Get element from queue (non-blocking)
     * @param result Output parameter to store retrieved element
     * @return Whether retrieval was successful
     */
    bool pop(T& result) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        if (data_queue.empty()) {
            return false;
        }
        
        result = std::move(data_queue.front());
        data_queue.pop();
        condition.notify_one(); // Notify possible waiting push operations
        return true;
    }

    /**
     * @brief Blocking get element from queue
     * @param result Output parameter to store retrieved element
     * @param timeout_ms Timeout in milliseconds, 0 means infinite wait
     * @return Whether retrieval was successful
     */
    bool pop_blocking(T& result, uint32_t timeout_ms = 0) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        
        auto wait_condition = [this] { 
            return !data_queue.empty() || shutdown.load(); 
        };
        
        if (timeout_ms > 0) {
            if (!condition.wait_for(lock, std::chrono::milliseconds(timeout_ms), wait_condition)) {
                return false; // Timeout
            }
        } else {
            condition.wait(lock, wait_condition);
        }
        
        if (shutdown.load() && data_queue.empty()) {
            return false;
        }
        
        if (!data_queue.empty()) {
            result = std::move(data_queue.front());
            data_queue.pop();
            condition.notify_one();
            return true;
        }
        
        return false;
    }

    /**
     * @brief Get front element without removing (non-blocking)
     * @param result Output parameter to store front element
     * @return Whether retrieval was successful
     */
    bool front(T& result) const {
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        if (data_queue.empty()) {
            return false;
        }
        
        result = data_queue.front();
        return true;
    }

    /**
     * @brief Check if queue is empty
     * @return Whether queue is empty
     */
    bool empty() const {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return data_queue.empty();
    }

    /**
     * @brief Get queue size
     * @return Number of elements in queue
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(queue_mutex);
        return data_queue.size();
    }

    /**
     * @brief Clear queue
     */
    void clear() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        std::queue<T> empty_queue;
        data_queue.swap(empty_queue);
        condition.notify_all();
    }

    /**
     * @brief Set maximum queue size
     * @param new_max_size New maximum size, 0 means unlimited
     */
    void set_max_size(size_t new_max_size) {
        max_size.store(new_max_size);
        condition.notify_all();
    }

    /**
     * @brief Get maximum queue size
     * @return Maximum queue size
     */
    size_t get_max_size() const {
        return max_size.load();
    }

    /**
     * @brief Shutdown queue and wake all waiting threads
     */
    void shutdown_queue() {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            shutdown.store(true);
        }
        condition.notify_all();
    }

    /**
     * @brief Check if queue is shutdown
     * @return Whether queue is shutdown
     */
    bool is_shutdown() const {
        return shutdown.load();
    }

    /**
     * @brief Restart shutdown queue
     */
    void restart() {
        std::lock_guard<std::mutex> lock(queue_mutex);
        shutdown.store(false);
    }
};

/**
 * @class QueueManager
 * @brief Queue manager for managing multiple named queues
 * @tparam T Queue element type
 */
template<typename T>
class QueueManager {
private:
    std::unordered_map<std::string, std::shared_ptr<ThreadSafeQueue<T>>> queues;
    mutable std::mutex manager_mutex;

public:
    /**
     * @brief Create or get named queue
     * @param name Queue name
     * @param max_size Maximum queue size
     * @return Shared pointer to queue
     */
    std::shared_ptr<ThreadSafeQueue<T>> get_queue(const std::string& name, size_t max_size = 0) {
        std::lock_guard<std::mutex> lock(manager_mutex);
        
        auto it = queues.find(name);
        if (it != queues.end()) {
            return it->second;
        }
        
        auto queue = std::make_shared<ThreadSafeQueue<T>>(max_size);
        queues[name] = queue;
        return queue;
    }

    /**
     * @brief Remove named queue
     * @param name Queue name
     * @return Whether deletion was successful
     */
    bool remove_queue(const std::string& name) {
        std::lock_guard<std::mutex> lock(manager_mutex);
        
        auto it = queues.find(name);
        if (it != queues.end()) {
            it->second->shutdown_queue();
            queues.erase(it);
            return true;
        }
        return false;
    }

    /**
     * @brief Get all queue names
     * @return List of queue names
     */
    std::vector<std::string> get_queue_names() const {
        std::lock_guard<std::mutex> lock(manager_mutex);
        std::vector<std::string> names;
        names.reserve(queues.size());
        
        for (const auto& pair : queues) {
            names.push_back(pair.first);
        }
        
        return names;
    }

    /**
     * @brief Shutdown all queues
     */
    void shutdown_all() {
        std::lock_guard<std::mutex> lock(manager_mutex);
        for (auto& pair : queues) {
            pair.second->shutdown_queue();
        }
    }

    /**
     * @brief Clear all queues
     */
    void clear_all() {
        std::lock_guard<std::mutex> lock(manager_mutex);
        queues.clear();
    }

    /**
     * @brief Get queue count
     * @return Queue count
     */
    size_t queue_count() const {
        std::lock_guard<std::mutex> lock(manager_mutex);
        return queues.size();
    }
};

#endif // THREAD_SAFE_QUEUE_HPP