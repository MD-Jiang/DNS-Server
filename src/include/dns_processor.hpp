#pragma once

#include "dns_cache.hpp"
#include "dns_message.hpp"
#include "zone.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>

struct ProcessorConfig {
    std::vector<std::string> upstreams;
    std::uint16_t upstream_port = 53;
    std::size_t udp_payload = 1232;
    std::uint32_t timeout_ms = 2000;
    std::uint32_t retries = 1;
};

struct DnsQueryPlan {
    enum class Action { Response, Upstream, Failure } action = Action::Failure;
    std::uint16_t original_id = 0;
    bool tcp = false;
    std::vector<std::uint8_t> response;
    std::vector<std::uint8_t> query;
    DnsQuestion question;
};

class DnsProcessor {
public:
    DnsProcessor(ZoneStore zone, ProcessorConfig config, std::size_t cache_size);
    std::vector<std::uint8_t> process(const std::uint8_t* data, std::size_t length,
                                      bool tcp) const;
    std::vector<std::uint8_t> overload_response(const std::uint8_t* data,
                                                std::size_t length, bool tcp) const;
    bool prepare(const std::uint8_t* data, std::size_t length, bool tcp,
                 DnsQueryPlan& plan, std::string& error) const;
    std::vector<std::uint8_t> finish_upstream(const DnsQueryPlan& plan,
                                              const std::uint8_t* data,
                                              std::size_t length) const;
    bool load_error() const noexcept;
    const std::string& error() const noexcept;

private:
    std::vector<std::uint8_t> make_local_response(const DnsMessage& request, bool tcp) const;
    std::vector<std::uint8_t> forward(const std::uint8_t* data, std::size_t length,
                                      const DnsMessage& request) const;
    static std::string cache_key(const DnsQuestion& question);
    static void replace_id(std::vector<std::uint8_t>& response, std::uint16_t id);

    ZoneStore zone_;
    ProcessorConfig config_;
    mutable DnsCache cache_;
    bool load_error_ = false;
    std::string error_;
};
