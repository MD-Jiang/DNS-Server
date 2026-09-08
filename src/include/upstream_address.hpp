#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <netdb.h>
#include <string>
#include <sys/socket.h>

inline bool parse_upstream_address(const std::string& value, sockaddr_in& address) {
    std::string host = value;
    std::uint16_t port = 53;
    const std::size_t separator = value.rfind(':');
    if (separator != std::string::npos && value.find(':') == separator) {
        host = value.substr(0, separator);
        try {
            const unsigned long parsed_port = std::stoul(value.substr(separator + 1));
            if (parsed_port > 65535) return false;
            port = static_cast<std::uint16_t>(parsed_port);
        } catch (...) {
            return false;
        }
    }
    if (host.empty()) return false;
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) == 1) return true;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) return false;
    address.sin_addr = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;
    freeaddrinfo(result);
    return true;
}