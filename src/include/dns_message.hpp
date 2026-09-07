#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class DnsRcode : std::uint8_t {
    NoError = 0,
    FormError = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImplemented = 4,
    Refused = 5
};

struct DnsFlags {
    bool qr = false;
    std::uint8_t opcode = 0;
    bool aa = false;
    bool tc = false;
    bool rd = false;
    bool ra = false;
    std::uint8_t z = 0;
    DnsRcode rcode = DnsRcode::NoError;

    static DnsFlags from_wire(std::uint16_t value) noexcept;
    std::uint16_t to_wire() const noexcept;
};

struct DnsQuestion {
    std::string name;
    std::uint16_t type = 1;
    std::uint16_t klass = 1;
};

struct DnsResourceRecord {
    std::string name;
    std::uint16_t type = 1;
    std::uint16_t klass = 1;
    std::uint32_t ttl = 0;
    std::vector<std::uint8_t> rdata;
};

struct DnsMessage {
    std::uint16_t id = 0;
    DnsFlags flags;
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;
    std::vector<DnsResourceRecord> authorities;
    std::vector<DnsResourceRecord> additionals;

    static bool parse(const std::uint8_t* data, std::size_t length,
                      DnsMessage& message, std::string& error);
    std::vector<std::uint8_t> serialize(std::size_t max_size = 65535,
                                        bool* truncated = nullptr) const;
};

std::string normalize_dns_name(const std::string& name);
std::vector<std::uint8_t> encode_dns_name(const std::string& name);