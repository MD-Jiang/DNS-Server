#include "dns_cache.hpp"

#include <algorithm>

DnsCache::DnsCache(const std::size_t capacity) : capacity_(capacity) {
    constexpr std::size_t shard_count = 32;
    shards_.reserve(shard_count);
    for (std::size_t index = 0; index < shard_count; ++index) {
        shards_.push_back(std::make_unique<Shard>());
    }
}

void DnsCache::evict_expired_locked(Shard& shard) {
    const auto now = std::chrono::steady_clock::now();
    for (auto iterator = shard.lru.begin(); iterator != shard.lru.end();) {
        if (iterator->value.expires <= now) {
            shard.index.erase(iterator->key);
            iterator = shard.lru.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

bool DnsCache::get(const std::string& key,
                   std::shared_ptr<const std::vector<std::uint8_t>>& response) {
    Shard& shard = *shards_[std::hash<std::string>{}(key) % shards_.size()];
    std::lock_guard<std::mutex> lock(shard.mutex);
    const auto found = shard.index.find(key);
    if (found == shard.index.end()) return false;
    if (found->second->value.expires <= std::chrono::steady_clock::now()) {
        shard.lru.erase(found->second);
        shard.index.erase(found);
        return false;
    }
    shard.lru.splice(shard.lru.begin(), shard.lru, found->second);
    response = found->second->value.response;
    return true;
}

void DnsCache::put(std::string key, std::vector<std::uint8_t> response,
                   const std::uint32_t ttl, const bool negative) {
    if (capacity_ == 0) return;
    Shard& shard = *shards_[std::hash<std::string>{}(key) % shards_.size()];
    std::lock_guard<std::mutex> lock(shard.mutex);
    const auto expires = std::chrono::steady_clock::now() +
        std::chrono::seconds(std::max<std::uint32_t>(ttl, 1));
    const auto found = shard.index.find(key);
    if (found != shard.index.end()) {
        found->second->value = CacheValue{
            std::make_shared<const std::vector<std::uint8_t>>(std::move(response)), expires, negative};
        shard.lru.splice(shard.lru.begin(), shard.lru, found->second);
        return;
    }
    shard.lru.push_front(Entry{std::move(key), CacheValue{
        std::make_shared<const std::vector<std::uint8_t>>(std::move(response)), expires, negative}});
    shard.index[shard.lru.front().key] = shard.lru.begin();
    const std::size_t shard_capacity = (capacity_ + shards_.size() - 1) / shards_.size();
    while (shard.lru.size() > shard_capacity) {
        shard.index.erase(shard.lru.back().key);
        shard.lru.pop_back();
    }
}

void DnsCache::cleanup_expired() {
    for (const std::unique_ptr<Shard>& shard : shards_) {
        std::lock_guard<std::mutex> lock(shard->mutex);
        evict_expired_locked(*shard);
    }
}
