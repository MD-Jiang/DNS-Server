#include "dns_message.hpp"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <set>

namespace {

bool read_u16(const std::uint8_t* data, std::size_t length, std::size_t& offset,
              std::uint16_t& value) {
    if (data == nullptr || offset > length || length - offset < 2) return false;
    std::uint16_t wire_value = 0;
    std::memcpy(&wire_value, data + offset, sizeof(wire_value));
    offset += 2;
    value = ntohs(wire_value);
    return true;
}

bool read_u32(const std::uint8_t* data, std::size_t length, std::size_t& offset,
              std::uint32_t& value) {
    if (data == nullptr || offset > length || length - offset < 4) return false;
    std::uint32_t wire_value = 0;
    std::memcpy(&wire_value, data + offset, sizeof(wire_value));
    offset += 4;
    value = ntohl(wire_value);
    return true;
}

void write_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    const std::uint16_t wire_value = htons(value);
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&wire_value);
    output.insert(output.end(), bytes, bytes + sizeof(wire_value));
}

void write_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    const std::uint32_t wire_value = htonl(value);
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&wire_value);
    output.insert(output.end(), bytes, bytes + sizeof(wire_value));
}

bool decode_name(const std::uint8_t* data, std::size_t length, std::size_t& offset,
                 std::string& name, std::string& error) {
    if (data == nullptr || offset >= length) {
        error = "missing DNS name";
        return false;
    }
    std::size_t cursor = offset;
    bool jumped = false;
    std::size_t jumps = 0;
    std::set<std::size_t> visited;
    std::string decoded;
    while (true) {
        if (cursor >= length) {
            error = "truncated DNS name";
            return false;
        }
        const std::uint8_t label = data[cursor];
        if (label == 0) {
            if (!jumped) offset = cursor + 1;
            name = decoded.empty() ? "." : normalize_dns_name(decoded);
            return true;
        }
        if ((label & 0xc0U) == 0xc0U) {
            if (cursor + 1 >= length) {
                error = "truncated DNS compression pointer";
                return false;
            }
            const std::size_t target = (static_cast<std::size_t>(label & 0x3fU) << 8U) |
                                       data[cursor + 1];
            if (target >= length || ++jumps > 100 || !visited.insert(target).second) {
                error = "invalid DNS compression pointer";
                return false;
            }
            if (!jumped) {
                offset = cursor + 2;
                jumped = true;
            }
            cursor = target;
            continue;
        }
        if ((label & 0xc0U) != 0 || label > 63 || cursor + 1U + label > length) {
            error = "invalid DNS label";
            return false;
        }
        if (decoded.size() + label + (decoded.empty() ? 0U : 1U) > 253U) {
            error = "DNS name is too long";
            return false;
        }
        if (!decoded.empty()) decoded.push_back('.');
        decoded.append(reinterpret_cast<const char*>(data + cursor + 1), label);
        cursor += 1U + label;
    }
}

bool parse_record(const std::uint8_t* data, std::size_t length, std::size_t& offset,
                  DnsResourceRecord& record, std::string& error) {
    if (!decode_name(data, length, offset, record.name, error)) return false;
    std::uint16_t rdlength = 0;
    if (!read_u16(data, length, offset, record.type) ||
        !read_u16(data, length, offset, record.klass) ||
        !read_u32(data, length, offset, record.ttl) ||
        !read_u16(data, length, offset, rdlength) ||
        offset > length || length - offset < rdlength) {
        error = "truncated resource record";
        return false;
    }
    record.rdata.assign(data + offset, data + offset + rdlength);
    offset += rdlength;
    return true;
}

void write_name(const std::string& input, std::vector<std::uint8_t>& output) {
    const std::string name = normalize_dns_name(input);
    if (name == ".") {
        output.push_back(0);
        return;
    }
    std::size_t start = 0;
    while (start < name.size()) {
        const std::size_t end = name.find('.', start);
        const std::size_t count = end == std::string::npos ? name.size() - start : end - start;
        if (count > 63) return;
        output.push_back(static_cast<std::uint8_t>(count));
        output.insert(output.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                      name.begin() + static_cast<std::ptrdiff_t>(start + count));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    output.push_back(0);
}

void write_record(const DnsResourceRecord& record, std::vector<std::uint8_t>& output) {
    write_name(record.name, output);
    write_u16(output, record.type);
    write_u16(output, record.klass);
    write_u32(output, record.ttl);
    write_u16(output, static_cast<std::uint16_t>(std::min<std::size_t>(record.rdata.size(), 65535)));
    output.insert(output.end(), record.rdata.begin(), record.rdata.end());
}

} // namespace

DnsFlags DnsFlags::from_wire(const std::uint16_t value) noexcept {
    DnsFlags flags;
    flags.qr = (value & 0x8000U) != 0;
    flags.opcode = static_cast<std::uint8_t>((value >> 11U) & 0x0fU);
    flags.aa = (value & 0x0400U) != 0;
    flags.tc = (value & 0x0200U) != 0;
    flags.rd = (value & 0x0100U) != 0;
    flags.ra = (value & 0x0080U) != 0;
    flags.z = static_cast<std::uint8_t>((value >> 4U) & 0x07U);
    flags.rcode = static_cast<DnsRcode>(value & 0x0fU);
    return flags;
}

std::uint16_t DnsFlags::to_wire() const noexcept {
    return static_cast<std::uint16_t>((qr ? 0x8000U : 0U) |
        ((opcode & 0x0fU) << 11U) | (aa ? 0x0400U : 0U) |
        (tc ? 0x0200U : 0U) | (rd ? 0x0100U : 0U) |
        (ra ? 0x0080U : 0U) | ((z & 0x07U) << 4U) |
        (static_cast<std::uint8_t>(rcode) & 0x0fU));
}

std::string normalize_dns_name(const std::string& name) {
    if (name.empty() || name == ".") return ".";
    std::string result = name;
    while (!result.empty() && result.back() == '.') result.pop_back();
    std::transform(result.begin(), result.end(), result.begin(),
                   [](const unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return result + ".";
}

std::vector<std::uint8_t> encode_dns_name(const std::string& name) {
    std::vector<std::uint8_t> output;
    write_name(name, output);
    return output;
}

bool DnsMessage::parse(const std::uint8_t* data, const std::size_t length,
                       DnsMessage& message, std::string& error) {
    message = DnsMessage{};
    std::size_t offset = 0;
    std::uint16_t wire_flags = 0;
    std::uint16_t question_count = 0;
    std::uint16_t answer_count = 0;
    std::uint16_t authority_count = 0;
    std::uint16_t additional_count = 0;
    if (!read_u16(data, length, offset, message.id) ||
        !read_u16(data, length, offset, wire_flags) ||
        !read_u16(data, length, offset, question_count) ||
        !read_u16(data, length, offset, answer_count) ||
        !read_u16(data, length, offset, authority_count) ||
        !read_u16(data, length, offset, additional_count)) {
        error = "DNS header is truncated";
        return false;
    }
    message.flags = DnsFlags::from_wire(wire_flags);
    if (question_count > 128 || answer_count > 4096 || authority_count > 4096 || additional_count > 4096) {
        error = "DNS section count is too large";
        return false;
    }
    for (std::uint16_t index = 0; index < question_count; ++index) {
        DnsQuestion question;
        if (!decode_name(data, length, offset, question.name, error) ||
            !read_u16(data, length, offset, question.type) ||
            !read_u16(data, length, offset, question.klass)) {
            error = "truncated DNS question: " + error;
            return false;
        }
        message.questions.push_back(std::move(question));
    }
    auto parse_records = [&](const std::uint16_t count, std::vector<DnsResourceRecord>& records) {
        for (std::uint16_t index = 0; index < count; ++index) {
            DnsResourceRecord record;
            if (!parse_record(data, length, offset, record, error)) return false;
            if (&records == &message.additionals && record.type == 41 && record.name == ".") {
                if (message.edns_present) {
                    error = "multiple EDNS OPT records";
                    return false;
                }
                message.edns_present = true;
                message.edns_udp_payload = std::max<std::uint16_t>(record.klass, 512);
                message.edns_version = static_cast<std::uint8_t>((record.ttl >> 16U) & 0xffU);
                message.edns_dnssec_ok = (record.ttl & 0x8000U) != 0;
            }
            records.push_back(std::move(record));
        }
        return true;
    };
    return parse_records(answer_count, message.answers) &&
           parse_records(authority_count, message.authorities) &&
           parse_records(additional_count, message.additionals);
}

std::vector<std::uint8_t> DnsMessage::serialize(const std::size_t max_size,
                                                bool* truncated) const {
    std::vector<std::uint8_t> output;
    output.reserve(std::min<std::size_t>(max_size, 512));
    output.resize(12, 0);
    for (const DnsQuestion& question : questions) {
        write_name(question.name, output);
        write_u16(output, question.type);
        write_u16(output, question.klass);
    }
    std::size_t answer_count = 0;
    std::size_t authority_count = 0;
    std::size_t additional_count = 0;
    bool was_truncated = false;
    const std::vector<const std::vector<DnsResourceRecord>*> sections = {
        &answers, &authorities, &additionals};
    const std::array<std::size_t*, 3> counts = {
        &answer_count, &authority_count, &additional_count};
    for (std::size_t section = 0; section < sections.size(); ++section) {
        for (const DnsResourceRecord& record : *sections[section]) {
            const std::size_t previous_size = output.size();
            write_record(record, output);
            if (output.size() > max_size) {
                output.resize(previous_size);
                was_truncated = true;
                break;
            }
            ++*counts[section];
        }
        if (was_truncated) break;
    }
    DnsFlags output_flags = flags;
    output_flags.tc = was_truncated;
    auto write_header = [&output](const std::size_t offset, const std::uint16_t value) {
        const std::uint16_t wire_value = htons(value);
        std::memcpy(output.data() + offset, &wire_value, sizeof(wire_value));
    };
    write_header(0, id);
    write_header(2, output_flags.to_wire());
    write_header(4, static_cast<std::uint16_t>(std::min<std::size_t>(questions.size(), 65535)));
    write_header(6, static_cast<std::uint16_t>(std::min<std::size_t>(answer_count, 65535)));
    write_header(8, static_cast<std::uint16_t>(std::min<std::size_t>(authority_count, 65535)));
    write_header(10, static_cast<std::uint16_t>(std::min<std::size_t>(additional_count, 65535)));
    if (truncated != nullptr) *truncated = was_truncated;
    return output;
}
