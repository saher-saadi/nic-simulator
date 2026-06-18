#ifndef __L3__
#define __L3__

#include <string>
#include <vector>
#include <cstdint>
#include "common.hpp"
#include "packets.hpp"

// Represents a layer-3 (network) packet with parsing, validation, and processing
class l3_packet : public generic_packet {
public:
    // Build a packet from a raw input line
    explicit l3_packet(const std::string& src_line);
    virtual ~l3_packet() {}

    // Verify if the packet fits given IP, mask, MAC, and allowed ports
    bool validate_packet(common::open_port_vec port_list,
                         uint8_t ip_addr[common::IP_V4_SIZE],
                         uint8_t ip_mask,
                         uint8_t mac_addr[common::MAC_SIZE]) override;

    // Process packet content and update target memory if applicable
    bool proccess_packet(common::open_port_vec &open_ports,
                         uint8_t ip_addr[common::IP_V4_SIZE],
                         uint8_t ip_mask,
                         common::memory_dest &dst) override;

    // Convert the packet into a human-readable string
    bool as_string(std::string &packet) override;

private:
    std::string raw_;                   // raw packet text
    std::vector<std::string> fields_;   // tokenized packet fields

    // Parse an IPv4 address string into byte array
    static bool parse_ip(const std::string& s, uint8_t out[common::IP_V4_SIZE]);

    // Convert a string into a 32-bit integer
    static uint32_t parse_u32(const std::string& s);

    // Convert a hex string payload into byte sequence
    static bool parse_hex_payload(const std::string& s, std::vector<uint8_t>& out);

    // Compute checksum based on packet fields
    static uint64_t compute_l3_checksum(const std::vector<std::string>& fields);

    // Compare two IPv4 addresses for equality
    static bool ip_equal(const uint8_t a[common::IP_V4_SIZE], const uint8_t b[common::IP_V4_SIZE]);
};

#endif // __L3__
