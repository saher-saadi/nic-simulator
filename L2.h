#ifndef __L2__
#define __L2__

#include <string>
#include <vector>
#include <cstdint>
#include "common.hpp"
#include "packets.hpp"

// Represents a layer-2 (data link) packet with parsing and validation features
class l2_packet : public generic_packet {
public:
    // Create a packet instance from a raw line
    explicit l2_packet(const std::string& src_line);
    virtual ~l2_packet() {}

    // Check if this packet is valid with given MAC, IP, and port constraints
    bool validate_packet(common::open_port_vec port_list,
                         uint8_t ip_addr[common::IP_V4_SIZE],
                         uint8_t ip_mask,
                         uint8_t mac_addr[common::MAC_SIZE]) override;

    // Process the packet and update destination state if necessary
    bool proccess_packet(common::open_port_vec &open_ports,
                         uint8_t ip_addr[common::IP_V4_SIZE],
                         uint8_t ip_mask,
                         common::memory_dest &dst) override;

    // Represent the packet as a string
    bool as_string(std::string &packet) override;

private:
    std::string raw_;                   // original packet string
    std::vector<std::string> fields_;   // tokenized fields from raw
    std::string l3line_cached_;         // cached L3 line built after validation

    // Convert MAC string into byte array
    static bool parse_mac(const std::string& s, uint8_t out[common::MAC_SIZE]);

    // Parse IPv4 address from string into byte array
    static bool parse_ip(const std::string& s, uint8_t out[common::IP_V4_SIZE]);

    // Convert string to 32-bit integer
    static uint32_t parse_u32(const std::string& s);

    // Parse hex payload into sequence of bytes
    static bool parse_hex_payload(const std::string& s, std::vector<uint8_t>& out);

    // Calculate checksum sum for L2 packet, excluding the last field
    static uint64_t sum_bytes_for_l2_checksum_excluding_last(const std::vector<std::string>& fields);
};

#endif // __L2__
