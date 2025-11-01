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
 * @file             Logger.hpp
 * @brief            Logger.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This header file implements a comprehensive thread-safe logging system for the TPDC project.
 *
 */


/**
 * @file Logger.hpp
 * @brief TPDC Logging System
 *
 * Provides thread-safe logging functionality with support for:
 * 1. Multi-level logging (DEBUG, INFO, WARN, ERROR_LVL)
 * 2. Timestamp recording
 * 3. Function name and line number recording
 * 4. Console and file output
 * 5. Performance statistics
 */

#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <iostream>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <thread>
#include <unordered_map>
#include <atomic>
#include <cstring>

/**
 * @enum LogLevel
 * @brief Log level enumeration
 */
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR_LVL = 3
};


/**
 * @class Logger
 * @brief Thread-safe logger class
 */
class Logger {
private:
    static std::mutex log_mutex;
    static std::ofstream log_file;
    static LogLevel current_level;
    static bool console_output;
    static bool file_output;
    static std::string log_filename;
    static std::atomic<bool> initialized;

    // Performance statistics
    static std::unordered_map<std::string, std::chrono::steady_clock::time_point> function_start_times;
    static std::unordered_map<std::string, long long> function_call_counts;
    static std::unordered_map<std::string, long long> function_total_time_us;
    static std::mutex stats_mutex;

public:
    /**
     * @brief Initialize the logging system
     * @param filename Log file name
     * @param level Log level
     * @param enable_console Enable console output
     * @param enable_file Enable file output
     */
    static void initialize(const std::string& filename = "tpdc.log", 
                          LogLevel level = LogLevel::INFO,
                          bool enable_console = true,
                          bool enable_file = true) {
        {
            std::lock_guard<std::mutex> lock(log_mutex);
            
            if (initialized.load()) {
                return;
            }
            
            current_level = level;
            console_output = enable_console;
            file_output = enable_file;
            log_filename = filename;
            
            if (file_output) {
                log_file.open(filename, std::ios::app);
                if (!log_file.is_open()) {
                    std::cerr << "Failed to open log file: " << filename << std::endl;
                    file_output = false;
                }
            }
            
            initialized.store(true);
        }
        
        // Record initialization completion log outside lock to avoid deadlock
        log(LogLevel::INFO, "Logger", "Logging system initialized", __FILE__, __LINE__);
    }

    /**
     * @brief Shutdown the logging system
     */
    static void shutdown() {
        // Record shutdown log before actual shutdown to avoid deadlock
        if (initialized.load()) {
            log(LogLevel::INFO, "Logger", "Logging system shutdown", __FILE__, __LINE__);
        }
        
        std::lock_guard<std::mutex> lock(log_mutex);
        
        if (!initialized.load()) {
            return;
        }
        
        if (log_file.is_open()) {
            log_file.close();
        }
        
        initialized.store(false);
    }

    /**
     * @brief Record log message
     * @param level Log level
     * @param function Function name
     * @param message Log message
     * @param file File name
     * @param line Line number
     */
    static void log(LogLevel level, const std::string& function, 
                   const std::string& message, const char* file = "", int line = 0) {
        if (!initialized.load() || level < current_level) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(log_mutex);
        
        // Get current time
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        // Get thread ID
        auto thread_id = std::this_thread::get_id();

        // Format log message
        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";
        ss << "[" << levelToString(level) << "] ";
        ss << "[Thread-" << thread_id << "] ";
        ss << "[" << function << "] ";
        
        if (strlen(file) > 0 && line > 0) {
            // Display filename only, not full path
            const char* filename = strrchr(file, '/');
            if (!filename) filename = strrchr(file, '\\');
            if (!filename) filename = file;
            else filename++;

            ss << "[" << filename << ":" << line << "] ";
        }
        
        ss << message;
        
        std::string log_line = ss.str();
        
        // Output to console
        if (console_output) {
            if (level >= LogLevel::ERROR_LVL) {
                std::cerr << log_line << std::endl;
            } else {
                std::cout << log_line << std::endl;
            }
        }

        // Output to file
        if (file_output && log_file.is_open()) {
            log_file << log_line << std::endl;
            log_file.flush();
        }
    }

    /**
     * @brief Start function performance timing
     * @param function_name Function name
     */
    static void startTiming(const std::string& function_name) {
        std::lock_guard<std::mutex> lock(stats_mutex);
        
        auto thread_id = std::this_thread::get_id();
        std::stringstream ss;
        ss << function_name << "_" << thread_id;
        std::string key = ss.str();
        
        function_start_times[key] = std::chrono::steady_clock::now();
        function_call_counts[function_name]++;
    }

    /**
     * @brief End function performance timing
     * @param function_name Function name
     */
    static void endTiming(const std::string& function_name) {
        auto end_time = std::chrono::steady_clock::now();
        
        std::lock_guard<std::mutex> lock(stats_mutex);
        
        auto thread_id = std::this_thread::get_id();
        std::stringstream ss;
        ss << function_name << "_" << thread_id;
        std::string key = ss.str();
        
        auto it = function_start_times.find(key);
        if (it != function_start_times.end()) {
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
                end_time - it->second).count();
            
            function_total_time_us[function_name] += duration;
            function_start_times.erase(it);
            
            // Record execution time log
            std::stringstream msg;
            msg << "Execution time: " << duration << " μs";
            log(LogLevel::DEBUG, function_name, msg.str());
        }
    }

    /**
     * @brief Print performance statistics
     */
    static void printStats() {
        std::lock_guard<std::mutex> lock(stats_mutex);
        
        log(LogLevel::INFO, "Logger", "========== Performance Statistics Report ==========");

        for (const auto& [func_name, call_count] : function_call_counts) {
            auto total_time = function_total_time_us[func_name];
            auto avg_time = call_count > 0 ? total_time / call_count : 0;

            std::stringstream msg;
            msg << "Function: " << func_name
                << ", Call count: " << call_count
                << ", Total time: " << total_time << " μs"
                << ", Average time: " << avg_time << " μs";

            log(LogLevel::INFO, "Stats", msg.str());
        }

        log(LogLevel::INFO, "Logger", "==========================================");
    }

    /**
     * @brief Clear performance statistics data
     */
    static void clearStats() {
        std::lock_guard<std::mutex> lock(stats_mutex);
        function_start_times.clear();
        function_call_counts.clear();
        function_total_time_us.clear();
    }

    /**
     * @brief Set log level
     * @param level New log level
     */
    static void setLevel(LogLevel level) {
        current_level = level;
    }

    /**
     * @brief Get current log level
     * @return Current log level
     */
    static LogLevel getLevel() {
        return current_level;
    }

private:
    /**
     * @brief Convert log level to string
     * @param level Log level
     * @return Log level string
     */
    static std::string levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO ";
            case LogLevel::WARN:  return "WARN ";
            case LogLevel::ERROR_LVL: return "ERROR_LVL";
            default: return "UNKNOWN";
        }
    }
};

// Static member variable declarations - Move to separate .cpp file to avoid multiple definitions
// Or use inline variables (C++17) to avoid multiple definition issues
inline std::mutex Logger::log_mutex;
inline std::ofstream Logger::log_file;
inline LogLevel Logger::current_level = LogLevel::INFO;
inline bool Logger::console_output = true;
inline bool Logger::file_output = true;
inline std::string Logger::log_filename = "tpdc.log";
inline std::atomic<bool> Logger::initialized{false};

inline std::unordered_map<std::string, std::chrono::steady_clock::time_point> Logger::function_start_times;
inline std::unordered_map<std::string, long long> Logger::function_call_counts;
inline std::unordered_map<std::string, long long> Logger::function_total_time_us;
inline std::mutex Logger::stats_mutex;

/**
 * @class FunctionTimer
 * @brief RAII-style function timer
 */
class FunctionTimer {
private:
    std::string function_name;

public:
    explicit FunctionTimer(const std::string& func_name) : function_name(func_name) {
        Logger::startTiming(function_name);
    }
    
    ~FunctionTimer() {
        Logger::endTiming(function_name);
    }
};

// Convenience macro definitions
#define LOG_DEBUG(func, msg) Logger::log(LogLevel::DEBUG, func, msg, __FILE__, __LINE__)
#define LOG_INFO(func, msg) Logger::log(LogLevel::INFO, func, msg, __FILE__, __LINE__)
#define LOG_WARN(func, msg) Logger::log(LogLevel::WARN, func, msg, __FILE__, __LINE__)
#define LOG_ERROR(func, msg) Logger::log(LogLevel::ERROR_LVL, func, msg, __FILE__, __LINE__)

#define FUNCTION_TIMER() FunctionTimer timer(__FUNCTION__)
#define FUNCTION_LOG_ENTRY() LOG_INFO(__FUNCTION__, "=====================Function Entry=====================")
#define FUNCTION_LOG_EXIT() LOG_INFO(__FUNCTION__,  "=====================Function Exit=====================")

// Parameterized log macros
#define LOG_DEBUG_PARAM(func, msg, ...) do { \
    std::stringstream ss; \
    ss << msg; \
    Logger::log(LogLevel::DEBUG, func, ss.str(), __FILE__, __LINE__); \
} while(0)

#define LOG_INFO_PARAM(func, msg, ...) do { \
    std::stringstream ss; \
    ss << msg; \
    Logger::log(LogLevel::INFO, func, ss.str(), __FILE__, __LINE__); \
} while(0)

#define LOG_WARN_PARAM(func, msg, ...) do { \
    std::stringstream ss; \
    ss << msg; \
    Logger::log(LogLevel::WARN, func, ss.str(), __FILE__, __LINE__); \
} while(0)

#define LOG_ERROR_PARAM(func, msg, ...) do { \
    std::stringstream ss; \
    ss << msg; \
    Logger::log(LogLevel::ERROR_LVL, func, ss.str(), __FILE__, __LINE__); \
} while(0)



// Helper function to get current timestamp
inline std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "[%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";
    return ss.str();
}


#endif // LOGGER_HPP