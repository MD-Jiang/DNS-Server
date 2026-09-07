#include "zone.hpp"

#include <arpa/inet.h>
#include <array>
#include <fstream>
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

bool make_record(const std::string& name, const std::string& type,
                 const std::vector<std::string>& fields, DnsResourceRecord& record,
                 std::string& error) {
    if (fields.empty()) {
        error = "missing record data";
        return false;
    }
    record.name = normalize_dns_name(name);
    record.klass = 1;
    record.ttl = 300;
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
        record.rdata = encode_dns_name(fields[0]);
    } else if (type == "MX") {
        if (fields.size() < 2) { error = "MX needs preference and host"; return false; }
        std::uint16_t preference = 0;
        if (!parse_u16(fields[0], preference)) { error = "invalid MX preference"; return false; }
        record.type = 15;
        append_u16(record.rdata, preference);
        const auto host = encode_dns_name(fields[1]);
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
        const auto primary = encode_dns_name(fields[0]);
        const auto mailbox = encode_dns_name(fields[1]);
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
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) line.resize(comment);
        std::istringstream stream(line);
        std::string name;
        std::string type;
        if (!(stream >> name >> type)) continue;
        std::vector<std::string> fields;
        std::string field;
        while (stream >> field) fields.push_back(field);
        DnsResourceRecord record;
        if (!make_record(name, type, fields, record, error)) {
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
