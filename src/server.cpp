#include <iostream>
#include "dns_server.hpp"

#include <cstdlib>
#include <sstream>

namespace {

void print_usage(const char* program) {
    std::cerr << "Usage: " << program
              << " [--port N] [--upstream IP[:PORT],...] [--zone-file PATH]"
              << " [--threads N] [--cache-size N]\n";
}

bool parse_size(const std::string& text, std::size_t& value) {
    try {
        std::size_t consumed = 0;
        const unsigned long long parsed = std::stoull(text, &consumed);
        if (consumed != text.size()) return false;
        value = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

int main(int argc, char** argv) {
    DnsServer::Config config;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help") {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        if (index + 1 >= argc) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        const std::string value = argv[++index];
        std::size_t number = 0;
        if (argument == "--port" && parse_size(value, number) && number <= 65535) {
            config.port = static_cast<std::uint16_t>(number);
        } else if (argument == "--threads" && parse_size(value, number) && number > 0) {
            config.threads = number;
        } else if (argument == "--cache-size" && parse_size(value, number)) {
            config.cache_size = number;
        } else if (argument == "--zone-file") {
            config.zone_file = value;
        } else if (argument == "--upstream") {
            std::stringstream stream(value);
            std::string upstream;
            while (std::getline(stream, upstream, ',')) {
                if (!upstream.empty()) config.upstreams.push_back(upstream);
            }
        } else {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    DnsServer server(std::move(config));
    std::string error;
    if (!server.start(error)) {
        std::cerr << "DNS server failed: " << error << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
