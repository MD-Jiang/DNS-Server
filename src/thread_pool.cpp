#include "thread_pool.hpp"

#include <algorithm>

ThreadPool::ThreadPool(const std::size_t thread_count) {
    const std::size_t count = std::max<std::size_t>(thread_count, 1);
    workers_.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        workers_.emplace_back(&ThreadPool::worker, this);
    }
}

ThreadPool::~ThreadPool() { stop(); }

void ThreadPool::submit(std::function<void()> task) {
    if (!task) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) return;
        tasks_.push(std::move(task));
    }
    condition_.notify_one();
}

void ThreadPool::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) return;
        stopping_ = true;
    }
    condition_.notify_all();
    for (std::thread& worker_thread : workers_) {
        if (worker_thread.joinable()) worker_thread.join();
    }
    workers_.clear();
}

void ThreadPool::worker() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            condition_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
            if (stopping_ && tasks_.empty()) return;
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        try {
            task();
        } catch (...) {
            // A failed request must not terminate the worker thread.
        }
    }
}
