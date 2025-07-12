//
// Created by TheLight233 on 2025/7/12.
//

#ifndef LOGSYSTEM_LUMINLOG_H
#define LOGSYSTEM_LUMINLOG_H

#include <iostream>
#include <queue>
#include <string>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <fstream>
#include <chrono>
#include <atomic>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <locale>
#include <codecvt>

// 平台检测宏
#if defined(_WIN32) || defined(_WIN64)
#define LUMIN_WINDOWS 1
#include <Windows.h>
#else
#define LUMIN_WINDOWS 0
#endif

enum class LogLevel
{
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3
};

constexpr bool operator<(LogLevel a, LogLevel b) {
    return static_cast<int>(a) < static_cast<int>(b);
}

std::string get_log_level_helper(LogLevel level)
{
    switch (level)
    {
        case LogLevel::Info:
            return "[Info] ";
        case LogLevel::Debug:
            return "[Debug] ";
        case LogLevel::Warning:
            return "[Warning] ";
        case LogLevel::Error:
            return "[Error] ";
        default:
            return "[Unknown] ";
    }
}

template<typename T>
std::string to_string_helper(T&& value)
{
    std::ostringstream oss;
    oss << std::forward<T>(value);
    return oss.str();
}

class LogQueue
{
public:
    void push(std::string&& msg)
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _queue.push(std::move(msg));
        _cond_var.notify_one();
    }

    bool pop(std::string& msg)
    {
        std::unique_lock<std::mutex> lock(_mutex);
        _cond_var.wait(lock, [this]() {
            return !_queue.empty() || is_shut_down;
        });

        if (is_shut_down && _queue.empty())
            return false;

        msg = std::move(_queue.front());
        _queue.pop();
        return true;
    }

    void shutdown()
    {
        std::lock_guard<std::mutex> lock(_mutex);
        is_shut_down = true;
        _cond_var.notify_all();
    }

private:
    std::queue<std::string> _queue;
    std::mutex _mutex;
    std::condition_variable _cond_var;
    std::atomic<bool> is_shut_down{false};
};

class Logger
{
public:
    explicit Logger(const std::string & filename) :
            _log_file(filename, std::ios::out | std::ios::app),
            _exit_flag(false)
    {
        if (!_log_file.is_open())
        {
            throw std::runtime_error("Fail to open log file.");
        }

        // 设置日志文件为UTF-8编码
#if LUMIN_WINDOWS
        constexpr unsigned char utf8_bom[] = {0xEF, 0xBB, 0xBF};
        _log_file.write(reinterpret_cast<const char*>(utf8_bom), sizeof(utf8_bom));
#endif

        _worker_thread = std::thread([this]() {
            const size_t batch_size = 10;
            std::vector<std::string> batch;
            batch.reserve(batch_size);

            while (true)
            {
                std::string msg;
                if (!_log_queue.pop(msg)) break;

                batch.push_back(std::move(msg));

                if (batch.size() >= batch_size)
                {
                    writeBatch(batch);
                    batch.clear();
                    batch.reserve(batch_size);
                }
            }

            writeBatch(batch);
        });

        // 在Windows上设置控制台编码为UTF-8
#if LUMIN_WINDOWS
        SetConsoleOutputCP(65001); // UTF-8代码页
#endif
    }

    ~Logger()
    {
        _exit_flag = true;
        _log_queue.shutdown();
        if (_worker_thread.joinable())
        {
            _worker_thread.join();
        }

        if (_log_file.is_open())
        {
            _log_file.close();
        }
    }

    template<typename ...Args>
    void log(const std::string & msg, Args&& ... args)
    {
        logImpl(LogLevel::Info, msg, std::forward<Args>(args)...);
    }

    void log(const std::string & msg)
    {
        logImpl(LogLevel::Info, msg);
    }

    template<typename ...Args>
    void debug(const std::string & msg, Args&& ... args)
    {
        logImpl(LogLevel::Debug, msg, std::forward<Args>(args)...);
    }

    void debug(const std::string & msg)
    {
        logImpl(LogLevel::Debug, msg);
    }

    template<typename ...Args>
    void warning(const std::string & msg, Args&& ... args)
    {
        logImpl(LogLevel::Warning, msg, std::forward<Args>(args)...);
    }

    void warning(const std::string & msg)
    {
        logImpl(LogLevel::Warning, msg);
    }

    template<typename ...Args>
    void error(const std::string & msg, Args&& ... args)
    {
        logImpl(LogLevel::Error, msg, std::forward<Args>(args)...);
    }

    void error(const std::string & msg)
    {
        logImpl(LogLevel::Error, msg);
    }

    void set_console(bool open)
    {
        console_output = open;
    }

    void set_min_level(LogLevel level) {
        min_level = level;
    }

private:
    void writeBatch(std::vector<std::string>& batch)
    {
        if (batch.empty()) return;

        for (auto& s : batch) {
            _log_file << s << '\n';
        }
        _log_file.flush();
    }

    static std::string getCurrentTime()
    {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;

        std::time_t time = std::chrono::system_clock::to_time_t(now);
        std::tm tm = *std::localtime(&time);

        char buffer[32];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);

        char result[36];
        std::snprintf(result, sizeof(result), "%s.%03d", buffer, static_cast<int>(ms.count()));
        return result;
    }

    // 在控制台正确输出UTF-8字符串
    static void safe_console_output(const std::string& str) {
#if LUMIN_WINDOWS
        // Windows需要特殊处理UTF-8输出
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            // 直接写入UTF-8编码的字符串
            WriteConsoleA(hConsole, str.c_str(), (DWORD)str.size(), &written, nullptr);
            WriteConsoleA(hConsole, "\n", 1, &written, nullptr);
        } else {
            // 回退方案
            std::cout << str << '\n';
        }
#else
        // Linux/macOS 直接输出
        std::cout << str << '\n';
#endif
    }

    template<typename ...Args>
    void logImpl(LogLevel level, const std::string& msg, Args&& ... args)
    {
        if (level < min_level) return;

        std::string str = formatMessage(level, msg, std::forward<Args>(args)...);
        if (str.empty()) return;

        if (console_output) {
            safe_console_output(str);
        }
        _log_queue.push(std::move(str));
    }

    void logImpl(LogLevel level, const std::string& msg)
    {
        if (level < min_level) return;

        std::string str;
        str.reserve(64 + msg.size());
        str.append(get_log_level_helper(level))
                .append(" [")
                .append(getCurrentTime())
                .append("] ")
                .append(msg);

        if (console_output) {
            safe_console_output(str);
        }
        _log_queue.push(std::move(str));
    }

    template<typename ...Args>
    std::string formatMessage(LogLevel level, const std::string& format, Args && ... args)
    {
        if (level < min_level) return "";

        const size_t num_args = sizeof...(Args);
        std::vector<std::string> arg_strings;
        arg_strings.reserve(num_args);

        (arg_strings.emplace_back(to_string_helper(std::forward<Args>(args))), ...);

        std::string result;
        result.reserve(64 + format.size() * 2);  // 预分配空间

        size_t arg_index = 0;
        size_t pos = 0;
        size_t placeHolder = format.find("{}", pos);

        while(placeHolder != std::string::npos)
        {
            result.append(format, pos, placeHolder - pos);
            if (arg_index < arg_strings.size()) {
                result.append(arg_strings[arg_index++]);
            } else {
                result.append("{}");
            }
            pos = placeHolder + 2;
            placeHolder = format.find("{}", pos);
        }
        result.append(format, pos, format.size() - pos);

        while (arg_index < arg_strings.size()) {
            result.append(arg_strings[arg_index++]);
        }

        std::string level_str = get_log_level_helper(level);
        result.insert(0, "] ");
        result.insert(0, getCurrentTime());
        result.insert(0, " [");
        result.insert(0, level_str);

        return result;
    }

    bool console_output = true;
    LogLevel min_level = LogLevel::Debug;
    LogQueue _log_queue;
    std::thread _worker_thread;
    std::ofstream _log_file;
    std::atomic<bool> _exit_flag;
};

#endif //LOGSYSTEM_LUMINLOG_H