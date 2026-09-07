#pragma once

#include "dns_message.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

class ZoneStore {
public:
    bool load(const std::string& path, std::string& error);
    std::vector<DnsResourceRecord> lookup(const std::string& name, std::uint16_t type,
                                          std::uint16_t klass = 1) const;
    bool contains_name(const std::string& name) const;

private:
    std::unordered_map<std::string, std::vector<DnsResourceRecord>> records_;
};
