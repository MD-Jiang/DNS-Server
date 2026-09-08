#include "zone.hpp"

#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <fstream>
#include <algorithm>
#include <filesystem>

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

std::string strip_zone_comment(const std::string& line) {
    bool quoted = false;
    bool escaped = false;
    for (std::size_t index = 0; index < line.size(); ++index) {
        const char character = line[index];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (character == '\\') {
            escaped = true;
            continue;
        }
        if (character == '"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted && (character == ';' || character == '#')) return line.substr(0, index);
    }
    return line;
}

bool tokenize_zone_line(const std::string& line, std::vector<std::string>& tokens,
                        std::string& error) {
    tokens.clear();
    std::string token;
    bool quoted = false;
    bool escaped = false;
    auto flush = [&]() {
        if (!token.empty()) {
            tokens.push_back(std::move(token));
            token.clear();
        }
    };
    for (const char character : line) {
        if (escaped) {
            token.push_back('\\');
            token.push_back(character);
            escaped = false;
        } else if (character == '\\') {
            escaped = true;
        } else if (character == '"') {
            quoted = !quoted;
        } else if (!quoted && (std::isspace(static_cast<unsigned char>(character)) ||
                               character == '(' || character == ')')) {
            flush();
        } else {
            token.push_back(character);
        }
    }
    if (escaped || quoted) {
        error = "unterminated quoted or escaped zone field";
        return false;
    }
    flush();
    return true;
}

std::string decode_txt(const std::string& value) {
    std::string output;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] != '\\' || index + 1 >= value.size()) {
            output.push_back(value[index]);
            continue;
        }
        if (index + 3 < value.size() && std::isdigit(static_cast<unsigned char>(value[index + 1])) &&
            std::isdigit(static_cast<unsigned char>(value[index + 2])) &&
            std::isdigit(static_cast<unsigned char>(value[index + 3]))) {
            const int number = (value[index + 1] - '0') * 100 +
                               (value[index + 2] - '0') * 10 + value[index + 3] - '0';
            output.push_back(static_cast<char>(number & 0xff));
            index += 3;
        } else {
            output.push_back(value[++index]);
        }
    }
    return output;
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
        for (const std::string& field : fields) {
            const std::string text = decode_txt(field);
            if (text.size() > 255) { error = "TXT string is too long"; return false; }
            record.rdata.push_back(static_cast<std::uint8_t>(text.size()));
            record.rdata.insert(record.rdata.end(), text.begin(), text.end());
        }
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
    records_.clear();
    domain_names_.clear();
    std::string origin = ".";
    std::uint32_t default_ttl = 300;
    return load_file(path, error, origin, default_ttl, 0);
}

bool ZoneStore::load_file(const std::string& path, std::string& error, std::string& origin,
                          std::uint32_t& default_ttl, const std::size_t depth) {
    if (depth > 16) {
        error = "zone $INCLUDE nesting is too deep";
        return false;
    }
    std::ifstream input(path);
    if (!input) {
        error = "cannot open zone file: " + path;
        return false;
    }
    std::string line;
    std::string logical_line;
    std::size_t line_number = 0;
    int parenthesis_depth = 0;
    while (std::getline(input, line)) {
        ++line_number;
        line = strip_zone_comment(line);
        bool quoted = false;
        bool escaped = false;
        for (const char character : line) {
            if (escaped) { escaped = false; continue; }
            if (character == '\\') { escaped = true; continue; }
            if (character == '"') { quoted = !quoted; continue; }
            if (!quoted && character == '(') ++parenthesis_depth;
            if (!quoted && character == ')') --parenthesis_depth;
            if (parenthesis_depth < 0) {
                error = "zone line " + std::to_string(line_number) + ": unexpected ')'";
                return false;
            }
        }
        logical_line += " " + line;
        if (parenthesis_depth != 0) continue;
        std::vector<std::string> tokens;
        std::string tokenize_error;
        if (!tokenize_zone_line(logical_line, tokens, tokenize_error)) {
            error = "zone line " + std::to_string(line_number) + ": " + tokenize_error;
            return false;
        }
        logical_line.clear();
        if (tokens.empty()) continue;
        const std::string& directive = tokens.front();
        if (directive == "$ORIGIN") {
            if (tokens.size() != 2) {
                error = "zone line " + std::to_string(line_number) + ": invalid $ORIGIN";
                return false;
            }
            origin = normalize_dns_name(tokens[1]);
            continue;
        }
        if (directive == "$TTL") {
            if (tokens.size() != 2 || !parse_u32(tokens[1], default_ttl)) {
                error = "zone line " + std::to_string(line_number) + ": invalid $TTL";
                return false;
            }
            continue;
        }
        if (directive == "$INCLUDE") {
            if (tokens.size() < 2 || tokens.size() > 3) {
                error = "zone line " + std::to_string(line_number) + ": invalid $INCLUDE";
                return false;
            }
            std::string include_origin = tokens.size() == 3 ? normalize_dns_name(tokens[2]) : origin;
            const std::filesystem::path include_path =
                std::filesystem::path(path).parent_path() / tokens[1];
            if (!load_file(include_path.lexically_normal().string(), error, include_origin,
                           default_ttl, depth + 1)) {
                return false;
            }
            continue;
        }
        if (tokens.size() < 2) {
            error = "zone line " + std::to_string(line_number) + ": missing record fields";
            return false;
        }
        std::string name = tokens.front();
        tokens.erase(tokens.begin());
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
        DnsResourceRecord record;
        if (!make_record(name, type, fields, record, error, origin, record_ttl)) {
            error = "zone line " + std::to_string(line_number) + ": " + error;
            return false;
        }
        domain_names_.insert(record.name);
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
    return domain_names_.find(normalize_dns_name(name)) != domain_names_.end();
}
