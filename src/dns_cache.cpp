#include "dns_cache.hpp"

#include <algorithm>

DnsCache::DnsCache(const std::size_t capacity) : capacity_(capacity) {}

void DnsCache::evict_expired_locked() {
    const auto now = std::chrono::steady_clock::now();
    for (auto iterator = lru_.begin(); iterator != lru_.end();) {
        if (iterator->value.expires <= now) {
            index_.erase(iterator->key);
            iterator = lru_.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

bool DnsCache::get(const std::string& key, std::vector<std::uint8_t>& response) {
    std::lock_guard<std::mutex> lock(mutex_);
    evict_expired_locked();
    const auto found = index_.find(key);
    if (found == index_.end()) return false;
    lru_.splice(lru_.begin(), lru_, found->second);
    response = found->second->value.response;
    return true;
}

void DnsCache::put(std::string key, std::vector<std::uint8_t> response,
                   const std::uint32_t ttl, const bool negative) {
    if (capacity_ == 0) return;
    std::lock_guard<std::mutex> lock(mutex_);
    const auto expires = std::chrono::steady_clock::now() +
        std::chrono::seconds(std::max<std::uint32_t>(ttl, 1));
    const auto found = index_.find(key);
    if (found != index_.end()) {
        found->second->value = CacheValue{std::move(response), expires, negative};
        lru_.splice(lru_.begin(), lru_, found->second);
        return;
    }
    lru_.push_front(Entry{std::move(key), CacheValue{std::move(response), expires, negative}});
    index_[lru_.front().key] = lru_.begin();
    while (lru_.size() > capacity_) {
        index_.erase(lru_.back().key);
        lru_.pop_back();
    }
}
