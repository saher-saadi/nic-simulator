#ifndef __L4__
#define __L4__

#include <string>
#include <vector>
#include <cstdint>
#include "common.hpp"
#include "packets.hpp"

// Represents a layer-4 packet with parsing and validation abilities
class l4_packet : public generic_packet {
public:
    // Construct a packet object from a raw line of text
    explicit l4_packet(const std::string& src_line);
    virtual ~l4_packet() {}

    // Check if the packet matches allowed ports, IP, and MAC
    bool validate_packet(common::open_port_vec port_list,
                         uint8_t ip_addr[common::IP_V4_SIZE],
                         uint8_t ip_mask,
                         uint8_t mac_addr[common::MAC_SIZE]) override;

    // Handle the packet and update memory/destination state if needed
    bool proccess_packet(common::open_port_vec &open_ports,
                         uint8_t ip_addr[common::IP_V4_SIZE],
                         uint8_t ip_mask,
                         common::memory_dest &dst) override;

    // Export the packet back into a readable string form
    bool as_string(std::string &packet) override;

private:
    std::string raw_;                   // original packet data as text
    std::vector<std::string> fields_;   // parsed fields from the raw input

    // Convert a string to a 32-bit integer
    static uint32_t parse_u32(const std::string& s);

    // Decode a hex string payload into bytes
    static bool parse_hex_payload(const std::string& s, std::vector<uint8_t>& out);
};

#endif // __L4__
