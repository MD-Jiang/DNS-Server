#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class ThreadPool {
public:
    ThreadPool(std::size_t thread_count, std::size_t max_queue_size);
    ~ThreadPool();
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    bool submit(std::function<void()> task);
    void stop();

private:
    void worker();
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::size_t max_queue_size_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool stopping_ = false;
};
