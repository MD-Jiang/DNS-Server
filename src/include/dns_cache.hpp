#pragma once

#include <chrono>
#include <cstddef>
#include <list>
#include <mutex>
#include <string>
#include <cstdint>
#include <vector>
#include <unordered_map>

struct CacheValue {
    std::vector<std::uint8_t> response;
    std::chrono::steady_clock::time_point expires;
    bool negative = false;
};

class DnsCache {
public:
    explicit DnsCache(std::size_t capacity);
    bool get(const std::string& key, std::vector<std::uint8_t>& response);
    void put(std::string key, std::vector<std::uint8_t> response, std::uint32_t ttl, bool negative);

private:
    struct Entry {
        std::string key;
        CacheValue value;
    };
    void evict_expired_locked();
    std::size_t capacity_;
    std::list<Entry> lru_;
    std::unordered_map<std::string, std::list<Entry>::iterator> index_;
    std::mutex mutex_;
};
