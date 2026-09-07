#include "dns_processor.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

bool parse_upstream(const std::string& value, sockaddr_in& address) {
    std::string host = value;
    std::uint16_t port = 53;
    const std::size_t separator = value.rfind(':');
    if (separator != std::string::npos && value.find(':') == separator) {
        host = value.substr(0, separator);
        try {
            port = static_cast<std::uint16_t>(std::stoul(value.substr(separator + 1)));
        } catch (...) {
            return false;
        }
    }
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

std::uint32_t minimum_ttl(const DnsMessage& message) {
    std::uint32_t ttl = 60;
    for (const auto& record : message.answers) ttl = std::min(ttl, record.ttl);
    for (const auto& record : message.authorities) ttl = std::min(ttl, record.ttl);
    return ttl;
}

} // namespace

DnsProcessor::DnsProcessor(ZoneStore zone, ProcessorConfig config, const std::size_t cache_size)
    : zone_(std::move(zone)), config_(std::move(config)), cache_(cache_size) {}

bool DnsProcessor::load_error() const noexcept { return load_error_; }
const std::string& DnsProcessor::error() const noexcept { return error_; }

std::string DnsProcessor::cache_key(const DnsQuestion& question) {
    return normalize_dns_name(question.name) + ":" + std::to_string(question.type) + ":" +
           std::to_string(question.klass);
}

void DnsProcessor::replace_id(std::vector<std::uint8_t>& response, const std::uint16_t id) {
    if (response.size() < 2) return;
    const std::uint16_t wire_id = htons(id);
    std::memcpy(response.data(), &wire_id, sizeof(wire_id));
}

std::vector<std::uint8_t> DnsProcessor::make_local_response(const DnsMessage& request,
                                                             const bool tcp) const {
    DnsMessage response;
    response.id = request.id;
    response.flags.qr = true;
    response.flags.opcode = request.flags.opcode;
    response.flags.rd = request.flags.rd;
    response.flags.aa = true;
    response.flags.ra = !config_.upstreams.empty();
    response.questions = request.questions;
    bool found_name = false;
    for (const auto& question : request.questions) {
        found_name = found_name || zone_.contains_name(question.name);
        auto records = zone_.lookup(question.name, question.type, question.klass);
        response.answers.insert(response.answers.end(), records.begin(), records.end());
    }
    if (!found_name && response.answers.empty()) response.flags.rcode = DnsRcode::NxDomain;
    bool truncated = false;
    return response.serialize(tcp ? 65535 : config_.udp_payload, &truncated);
}

std::vector<std::uint8_t> DnsProcessor::forward(const std::uint8_t* data, const std::size_t length,
                                                const DnsMessage& request) const {
    if (config_.upstreams.empty()) return make_local_response(request, false);
    std::vector<std::uint8_t> cached;
    if (!request.questions.empty() && cache_.get(cache_key(request.questions.front()), cached)) {
        replace_id(cached, request.id);
        return cached;
    }
    const int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) return {};
    std::vector<std::uint8_t> result;
    for (const std::string& upstream : config_.upstreams) {
        sockaddr_in address{};
        if (!parse_upstream(upstream, address)) continue;
        for (std::uint32_t attempt = 0; attempt <= config_.retries; ++attempt) {
            if (sendto(socket_fd, data, length, 0, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) continue;
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(socket_fd, &readable);
            timeval timeout{};
            timeout.tv_sec = static_cast<long>(config_.timeout_ms / 1000);
            timeout.tv_usec = static_cast<long>((config_.timeout_ms % 1000) * 1000);
            if (select(socket_fd + 1, &readable, nullptr, nullptr, &timeout) <= 0) continue;
            std::array<std::uint8_t, 65535> buffer{};
            const ssize_t received = recvfrom(socket_fd, buffer.data(), buffer.size(), 0, nullptr, nullptr);
            if (received <= 0) continue;
            DnsMessage upstream_response;
            std::string parse_error;
            if (!DnsMessage::parse(buffer.data(), static_cast<std::size_t>(received), upstream_response, parse_error) ||
                upstream_response.id != request.id || !upstream_response.flags.qr) continue;
            result.assign(buffer.begin(), buffer.begin() + received);
            if (!request.questions.empty()) {
                const bool negative = upstream_response.flags.rcode == DnsRcode::NxDomain;
                cache_.put(cache_key(request.questions.front()), result,
                           minimum_ttl(upstream_response), negative);
            }
            close(socket_fd);
            return result;
        }
    }
    close(socket_fd);
    DnsMessage failure;
    failure.id = request.id;
    failure.flags.qr = true;
    failure.flags.rd = request.flags.rd;
    failure.flags.ra = true;
    failure.flags.rcode = DnsRcode::ServFail;
    failure.questions = request.questions;
    return failure.serialize(config_.udp_payload);
}

std::vector<std::uint8_t> DnsProcessor::process(const std::uint8_t* data, const std::size_t length,
                                                const bool tcp) const {
    DnsMessage request;
    std::string parse_error;
    if (!DnsMessage::parse(data, length, request, parse_error) || request.flags.qr ||
        request.flags.opcode != 0 || request.questions.empty()) {
        DnsMessage failure;
        if (length >= 2) std::memcpy(&failure.id, data, sizeof(failure.id));
        failure.flags.qr = true;
        failure.flags.rcode = DnsRcode::FormError;
        return failure.serialize(tcp ? 65535 : config_.udp_payload);
    }
    if (request.questions.size() > 1) {
        return make_local_response(request, tcp);
    }
    if (zone_.contains_name(request.questions.front().name)) {
        return make_local_response(request, tcp);
    }
    return forward(data, length, request);
}
