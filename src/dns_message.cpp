#include "dns_message.hpp"
#include <cstring>
#include <string>
#include <arpa/inet.h>

// Constructor to initialize the DNS header with default values
Header::Header()
{
    this->tran_id = 0;
    this->flags = {0};
    this->question_count = 0;
    this->answer_count = 0;
    this->authority_count = 0;
    this->additional_count = 0;
}

// Function to set the header for a standard question
void Header::setStandardQery(std::uint16_t query_id)
{
    this->tran_id = query_id;
    this->flags = {
        .qr = 1,
        .opcode = 0,
        .aa = 0,
        .tc = 0,
        .rd = 0,
        .ra = 0,
        .z = 0,
        .rcode = 0};
    this->question_count = 1;
    this->answer_count = 0;
    this->authority_count = 0;
    this->additional_count = 0;
}

// Function to parse a DNS message from a buffer
void Header::parse(const std::uint8_t *buffer)
{
    this->question.qname.clear();
    this->tran_id = ntohs(*reinterpret_cast<const std::uint16_t *>(buffer));
    this->flags.fromUint16(ntohs(*reinterpret_cast<const std::uint16_t *>(buffer + 2)));
    this->question_count = ntohs(*reinterpret_cast<const std::uint16_t *>(buffer + 4));
    this->answer_count = ntohs(*reinterpret_cast<const std::uint16_t *>(buffer + 6));
    this->authority_count = ntohs(*reinterpret_cast<const std::uint16_t *>(buffer + 8));
    this->additional_count = ntohs(*reinterpret_cast<const std::uint16_t *>(buffer + 10));

    const std::uint8_t *qname_ptr = buffer + 12;
    while (*qname_ptr != 0)
    {
        const std::size_t label_length = *qname_ptr++;
        this->question.qname.emplace_back(
            reinterpret_cast<const char *>(qname_ptr), label_length);
        qname_ptr += label_length; 
    }

    this->question.qtype = ntohs(*reinterpret_cast<const std::uint16_t *>(qname_ptr + 1));
    this->question.qclass = ntohs(*reinterpret_cast<const std::uint16_t *>(qname_ptr + 3));
}

// Function to serialize the DNS header into a buffer
std::size_t Header::serialize(std::uint8_t *buffer) const
{
    *reinterpret_cast<std::uint16_t *>(buffer) = htons(this->tran_id);
    *reinterpret_cast<std::uint16_t *>(buffer + 2) = htons(this->flags.toUint16());
    *reinterpret_cast<std::uint16_t *>(buffer + 4) = htons(this->question_count);
    *reinterpret_cast<std::uint16_t *>(buffer + 6) = htons(this->answer_count);
    *reinterpret_cast<std::uint16_t *>(buffer + 8) = htons(this->authority_count);
    *reinterpret_cast<std::uint16_t *>(buffer + 10) = htons(this->additional_count);

    // Serialize the question
    uint8_t *qname_ptr = buffer + 12;
    int offset = 0;

    for (const std::string &label : this->question.qname) {
        const std::size_t label_length = label.size();
        
        qname_ptr[offset] = static_cast<uint8_t>(label_length);
        offset += 1;
        std::memcpy(qname_ptr + offset, label.data(), label_length);
        offset += label_length;
    }

    qname_ptr[offset] = 0;
    offset += 1;
    
    *reinterpret_cast<std::uint16_t *>(qname_ptr + offset) = htons(this->question.qtype);
    offset += 2;
    
    // Serialize QCLASS
    *reinterpret_cast<std::uint16_t *>(qname_ptr + offset) = htons(this->question.qclass);
    offset += 2;

    if (this->answer_count > 0) {
        *reinterpret_cast<std::uint16_t *>(qname_ptr + offset) = htons(0xc00c);
        offset += 2;

        *reinterpret_cast<std::uint16_t *>(qname_ptr + offset) = htons(1);
        offset += 2;

        *reinterpret_cast<std::uint16_t *>(qname_ptr + offset) = htons(1);
        offset += 2;

        *reinterpret_cast<std::uint32_t *>(qname_ptr + offset) = htonl(this->answer_ttl);
        offset += 4;

        *reinterpret_cast<std::uint16_t *>(qname_ptr + offset) = htons(4);
        offset += 2;

        std::memcpy(qname_ptr + offset, this->answer_address.data(), this->answer_address.size());
        offset += this->answer_address.size();
    }

    return 12 + offset;
}
