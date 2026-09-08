#include "dns_processor.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <chrono>
#include <cstring>

namespace {

std::uint32_t minimum_ttl(const DnsMessage& message) {
    std::uint32_t ttl = 60;
    for (const auto& record : message.answers) ttl = std::min(ttl, record.ttl);
    for (const auto& record : message.authorities) ttl = std::min(ttl, record.ttl);
    return ttl;
}

std::size_t response_payload(const DnsMessage& request, const ProcessorConfig& config, const bool tcp) {
    if (tcp) return 65535;
    if (!request.edns_present) return std::min<std::size_t>(config.udp_payload, 512);
    return std::min<std::size_t>(config.udp_payload, request.edns_udp_payload);
}

void append_opt_response(const DnsMessage& request, DnsMessage& response,
                         const ProcessorConfig& config) {
    if (!request.edns_present) return;
    DnsResourceRecord opt;
    opt.name = ".";
    opt.type = 41;
    opt.klass = static_cast<std::uint16_t>(std::min<std::size_t>(config.udp_payload,
                                                                 request.edns_udp_payload));
    opt.ttl = request.edns_dnssec_ok ? 0x8000U : 0U;
    response.additionals.push_back(std::move(opt));
}

} // namespace

DnsProcessor::DnsProcessor(ZoneStore zone, ProcessorConfig config, const std::size_t cache_size)
    : zone_(std::move(zone)), config_(std::move(config)), cache_(cache_size) {}

bool DnsProcessor::load_error() const noexcept { return load_error_; }
const std::string& DnsProcessor::error() const noexcept { return error_; }
void DnsProcessor::cleanup_cache() const { cache_.cleanup_expired(); }

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
    append_opt_response(request, response, config_);
    bool found_name = false;
    for (const auto& question : request.questions) {
        found_name = found_name || zone_.contains_name(question.name);
        auto records = zone_.lookup(question.name, question.type, question.klass);
        response.answers.insert(response.answers.end(), records.begin(), records.end());
    }
    if (!found_name && response.answers.empty()) response.flags.rcode = DnsRcode::NxDomain;
    bool truncated = false;
    return response.serialize(response_payload(request, config_, tcp), &truncated);
}

std::vector<std::uint8_t> DnsProcessor::overload_response(const std::uint8_t* data,
                                                          const std::size_t length,
                                                          const bool tcp) const {
    DnsMessage request;
    std::string error;
    if (!DnsMessage::parse(data, length, request, error)) return {};
    DnsMessage response;
    response.id = request.id;
    response.flags.qr = true;
    response.flags.rd = request.flags.rd;
    response.flags.ra = !config_.upstreams.empty();
    response.flags.rcode = DnsRcode::ServFail;
    response.questions = request.questions;
    append_opt_response(request, response, config_);
    return response.serialize(response_payload(request, config_, tcp));
}

bool DnsProcessor::prepare(const std::uint8_t* data, const std::size_t length,
                           const bool tcp, DnsQueryPlan& plan, std::string& error) const {
    plan = DnsQueryPlan{};
    plan.tcp = tcp;
    DnsMessage request;
    if (!DnsMessage::parse(data, length, request, error) || request.flags.qr ||
        request.flags.opcode != 0 || request.questions.empty()) {
        plan.action = DnsQueryPlan::Action::Failure;
        plan.response = overload_response(data, length, tcp);
        return false;
    }
    plan.original_id = request.id;
    plan.question = request.questions.front();
    bool all_questions_are_local = true;
    for (const DnsQuestion& question : request.questions) {
        all_questions_are_local = all_questions_are_local && zone_.contains_name(question.name);
    }
    if (all_questions_are_local || config_.upstreams.empty()) {
        plan.action = DnsQueryPlan::Action::Response;
        plan.response = make_local_response(request, tcp);
        return true;
    }
    std::shared_ptr<const std::vector<std::uint8_t>> cached;
    if (request.questions.size() == 1 && !config_.upstreams.empty() &&
        cache_.get(cache_key(plan.question), cached)) {
        plan.action = DnsQueryPlan::Action::Response;
        plan.response = *cached;
        replace_id(plan.response, request.id);
        return true;
    }
    plan.action = DnsQueryPlan::Action::Upstream;
    plan.query.assign(data, data + length);
    return true;
}

std::vector<std::uint8_t> DnsProcessor::finish_upstream(const DnsQueryPlan& plan,
                                                        const std::uint8_t* data,
                                                        const std::size_t length) const {
    DnsMessage response;
    std::string error;
    std::uint16_t wire_id = 0;
    if (length < 2) return {};
    std::memcpy(&wire_id, data, sizeof(wire_id));
    if (!DnsMessage::parse(data, length, response, error) ||
        !response.flags.qr || response.id != ntohs(wire_id)) {
        return {};
    }
    std::vector<std::uint8_t> output(data, data + length);
    replace_id(output, plan.original_id);
    cache_.put(cache_key(plan.question), output, minimum_ttl(response),
               response.flags.rcode == DnsRcode::NxDomain);
    return output;
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
    DnsQueryPlan plan;
    if (!prepare(data, length, tcp, plan, parse_error)) return plan.response;
    if (plan.action == DnsQueryPlan::Action::Response) return plan.response;
    return overload_response(data, length, tcp);
}
