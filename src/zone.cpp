#include "zone.hpp"

#include <arpa/inet.h>
#include <array>
#include <fstream>
#include <algorithm>
#include <sstream>

namespace {

bool parse_u32(const std::string& text, std::uint32_t& value) {
    try {
        std::size_t consumed = 0;
        const unsigned long parsed = std::stoul(text, &consumed);
        if (consumed != text.size() || parsed > 0xffffffffUL) return false;
        value = static_cast<std::uint32_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_u16(const std::string& text, std::uint16_t& value) {
    std::uint32_t parsed = 0;
    if (!parse_u32(text, parsed) || parsed > 65535) return false;
    value = static_cast<std::uint16_t>(parsed);
    return true;
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    const std::uint16_t wire = htons(value);
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&wire);
    output.insert(output.end(), bytes, bytes + sizeof(wire));
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    const std::uint32_t wire = htonl(value);
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&wire);
    output.insert(output.end(), bytes, bytes + sizeof(wire));
}

std::string qualify_name(const std::string& value, const std::string& origin) {
    if (value == "@") return normalize_dns_name(origin);
    if (value.empty() || value == "." || value.back() == '.') return normalize_dns_name(value);
    return normalize_dns_name(value + "." + origin);
}

bool make_record(const std::string& name, const std::string& type,
                 const std::vector<std::string>& fields, DnsResourceRecord& record,
                 std::string& error, const std::string& origin, const std::uint32_t ttl) {
    if (fields.empty()) {
        error = "missing record data";
        return false;
    }
    record.name = qualify_name(name, origin);
    record.klass = 1;
    record.ttl = ttl;
    record.rdata.clear();
    if (type == "A") {
        std::array<std::uint8_t, 4> address{};
        if (inet_pton(AF_INET, fields[0].c_str(), address.data()) != 1) {
            error = "invalid A address";
            return false;
        }
        record.type = 1;
        record.rdata.assign(address.begin(), address.end());
    } else if (type == "AAAA") {
        std::array<std::uint8_t, 16> address{};
        if (inet_pton(AF_INET6, fields[0].c_str(), address.data()) != 1) {
            error = "invalid AAAA address";
            return false;
        }
        record.type = 28;
        record.rdata.assign(address.begin(), address.end());
    } else if (type == "CNAME" || type == "NS") {
        record.type = type == "CNAME" ? 5 : 2;
        record.rdata = encode_dns_name(qualify_name(fields[0], origin));
    } else if (type == "MX") {
        if (fields.size() < 2) { error = "MX needs preference and host"; return false; }
        std::uint16_t preference = 0;
        if (!parse_u16(fields[0], preference)) { error = "invalid MX preference"; return false; }
        record.type = 15;
        append_u16(record.rdata, preference);
        const auto host = encode_dns_name(qualify_name(fields[1], origin));
        record.rdata.insert(record.rdata.end(), host.begin(), host.end());
    } else if (type == "TXT") {
        record.type = 16;
        const std::string text = fields[0];
        if (text.size() > 255) { error = "TXT string is too long"; return false; }
        record.rdata.push_back(static_cast<std::uint8_t>(text.size()));
        record.rdata.insert(record.rdata.end(), text.begin(), text.end());
    } else if (type == "SOA") {
        if (fields.size() < 7) { error = "SOA needs seven fields"; return false; }
        record.type = 6;
        const auto primary = encode_dns_name(qualify_name(fields[0], origin));
        const auto mailbox = encode_dns_name(qualify_name(fields[1], origin));
        record.rdata.insert(record.rdata.end(), primary.begin(), primary.end());
        record.rdata.insert(record.rdata.end(), mailbox.begin(), mailbox.end());
        for (std::size_t index = 2; index < 7; ++index) {
            std::uint32_t value = 0;
            if (!parse_u32(fields[index], value)) { error = "invalid SOA number"; return false; }
            append_u32(record.rdata, value);
        }
    } else {
        error = "unsupported record type: " + type;
        return false;
    }
    return true;
}

} // namespace

bool ZoneStore::load(const std::string& path, std::string& error) {
    std::ifstream input(path);
    if (!input) {
        error = "cannot open zone file: " + path;
        return false;
    }
    records_.clear();
    std::string line;
    std::string logical_line;
    std::string origin = ".";
    std::uint32_t default_ttl = 300;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        const std::size_t hash_comment = line.find('#');
        const std::size_t semicolon_comment = line.find(';');
        const std::size_t comment = std::min(hash_comment, semicolon_comment);
        if (comment != std::string::npos) line.resize(comment);
        logical_line += " " + line;
        const bool has_open = logical_line.find('(') != std::string::npos;
        const bool has_close = logical_line.find(')') != std::string::npos;
        if (has_open && !has_close) continue;
        std::replace(logical_line.begin(), logical_line.end(), '(', ' ');
        std::replace(logical_line.begin(), logical_line.end(), ')', ' ');
        std::istringstream stream(logical_line);
        logical_line.clear();
        std::string directive;
        if (!(stream >> directive)) continue;
        if (directive == "$ORIGIN") {
            if (!(stream >> origin)) { error = "invalid $ORIGIN"; return false; }
            origin = normalize_dns_name(origin);
            continue;
        }
        if (directive == "$TTL") {
            std::string value;
            if (!(stream >> value) || !parse_u32(value, default_ttl)) {
                error = "invalid $TTL";
                return false;
            }
            continue;
        }
        std::string name = directive;
        std::string token;
        std::vector<std::string> tokens;
        while (stream >> token) tokens.push_back(token);
        if (tokens.empty()) continue;
        std::uint32_t record_ttl = default_ttl;
        std::size_t index = 0;
        std::uint32_t parsed_ttl = 0;
        if (parse_u32(tokens[index], parsed_ttl)) {
            record_ttl = parsed_ttl;
            ++index;
        }
        if (index < tokens.size() && tokens[index] == "IN") ++index;
        if (index >= tokens.size()) {
            error = "missing record type";
            return false;
        }
        const std::string type = tokens[index++];
        std::vector<std::string> fields(tokens.begin() + static_cast<std::ptrdiff_t>(index), tokens.end());
        if (type == "TXT" && fields.size() == 1 && fields[0].size() >= 2 &&
            fields[0].front() == '"' && fields[0].back() == '"') {
            fields[0] = fields[0].substr(1, fields[0].size() - 2);
        }
        DnsResourceRecord record;
        if (!make_record(name, type, fields, record, error, origin, record_ttl)) {
            error = "zone line " + std::to_string(line_number) + ": " + error;
            return false;
        }
        records_[record.name + "\x1f" + std::to_string(record.type)].push_back(std::move(record));
    }
    return true;
}

std::vector<DnsResourceRecord> ZoneStore::lookup(const std::string& name, const std::uint16_t type,
                                                 const std::uint16_t klass) const {
    const auto key = normalize_dns_name(name) + "\x1f" + std::to_string(type);
    const auto found = records_.find(key);
    if (found == records_.end()) return {};
    std::vector<DnsResourceRecord> result;
    for (const auto& record : found->second) {
        if (record.klass == klass) result.push_back(record);
    }
    return result;
}

bool ZoneStore::contains_name(const std::string& name) const {
    const std::string prefix = normalize_dns_name(name) + "\x1f";
    for (const auto& entry : records_) {
        if (entry.first.compare(0, prefix.size(), prefix) == 0) return true;
    }
    return false;
}
