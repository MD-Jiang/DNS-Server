#include "dns_message.hpp"

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

int main() {
    const std::vector<std::uint8_t> compressed = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0x03, 'f', 'o', 'o', 0xc0, 0x10, 0x00, 0x1c, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 8, 8, 8, 8,
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    DnsMessage message;
    std::string error;
    assert(DnsMessage::parse(compressed.data(), compressed.size(), message, error));
    assert(message.questions.size() == 2);
    assert(message.questions[0].name == "www.example.com.");
    assert(message.questions[1].name == "foo.example.com.");
    assert(message.answers.size() == 1);
    assert(message.additionals.size() == 1);
    const auto encoded = message.serialize();
    DnsMessage roundtrip;
    assert(DnsMessage::parse(encoded.data(), encoded.size(), roundtrip, error));
    assert(roundtrip.questions.size() == 2);
    assert(roundtrip.answers.size() == 1);
    assert(roundtrip.additionals.size() == 1);
    return 0;
}
