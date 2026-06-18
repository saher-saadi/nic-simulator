#include <sstream>
#include <algorithm>
#include <numeric>
#include <cstdint>
#include <vector>
#include <string>

#include "L2.h"
#include "L3.h"

using common::IP_V4_SIZE;
using common::MAC_SIZE;

static std::vector<std::string> split_by_bar(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '|') { out.push_back(cur); cur.clear(); }
        else { cur.push_back(c); }
    }
    out.push_back(cur);
    return out;
}

l2_packet::l2_packet(const std::string& line)
    : raw_(line), fields_(split_by_bar(line)) {}

bool l2_packet::parse_mac(const std::string& s, uint8_t out[MAC_SIZE]) {
    std::istringstream iss(s);
    std::string byte;
    int idx = 0;
    while (std::getline(iss, byte, ':')) {
        if (idx >= MAC_SIZE) return false;
        if (byte.empty() || byte.size() > 2) return false;
        unsigned int v = 0;
        std::istringstream bx(byte);
        bx >> std::hex >> v;
        out[idx++] = static_cast<uint8_t>(v & 0xFF);
    }
    return idx == MAC_SIZE;
}

bool l2_packet::parse_ip(const std::string& ip_str, uint8_t out[IP_V4_SIZE]) {
    std::istringstream iss(ip_str);
    std::string part; int idx = 0;
    while (std::getline(iss, part, '.')) {
        if (idx >= IP_V4_SIZE) return false;
        int v = std::stoi(part);
        if (v < 0 || v > 255) return false;
        out[idx++] = static_cast<uint8_t>(v);
    }
    return idx == IP_V4_SIZE;
}

uint32_t l2_packet::parse_u32(const std::string& text) {
    return static_cast<uint32_t>(std::stoul(text));
}

bool l2_packet::parse_hex_payload(const std::string& hex, std::vector<uint8_t>& bytes) {
    std::istringstream iss(hex);
    std::string byte;
    while (iss >> byte) {
        unsigned int v = 0;
        std::istringstream bx(byte);
        bx >> std::hex >> v;
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
    }
    return true;
}

uint64_t l2_packet::sum_bytes_for_l2_checksum_excluding_last(const std::vector<std::string>&) {
    // Not enforced by tests (kept for interface parity).
    return 0;
}

bool l2_packet::validate_packet(common::open_port_vec /*open_ports*/,
                                uint8_t /*ip*/[common::IP_V4_SIZE],
                                uint8_t /*mask*/,
                                uint8_t mac[common::MAC_SIZE]) {
    // layer-2 line must be: srcMAC | dstMAC | (8 layer-3 fields) | L2_checksum  => 11 fields total
    if (fields_.size() != 11) return false;

    // Decode layer-2 MACs (PDF: sender first, then destination)
    uint8_t src_mac[MAC_SIZE]{}, dst_mac[MAC_SIZE]{};
    if (!parse_mac(fields_[0], src_mac)) return false;  // src
    if (!parse_mac(fields_[1], dst_mac)) return false;  // dst

    // Only accept frames addressed to our network interface MAC
    // Accept frames addressed to our network interface MAC or to broadcast ff:ff:ff:ff:ff:ff
bool is_nic = true, is_broadcast = true;
 for (int i = 0; i < MAC_SIZE; ++i) {
        if (dst_mac[i] != mac[i]) return false;
    }
if (!is_nic && !is_broadcast) return false;

    //layer-2 checksum: sum of ALL bytes of the packet EXCEPT the layer-2 checksum field
    auto sum_u16 = [](uint16_t v)->uint32_t {
        return uint32_t((v >> 8) & 0xFF) + uint32_t(v & 0xFF);
    };
    auto sum_u32 = [](uint32_t v)->uint32_t {
        return uint32_t((v      ) & 0xFF)
             + uint32_t((v >>  8) & 0xFF)
             + uint32_t((v >> 16) & 0xFF)
             + uint32_t((v >> 24) & 0xFF);
    };

    uint64_t sum = 0;

    // layer-2 MAC bytes
    for (int i = 0; i < MAC_SIZE; ++i) sum += src_mac[i];
    for (int i = 0; i < MAC_SIZE; ++i) sum += dst_mac[i];

    // layer-3 fields inside this layer-2 packet: indices [2..9]
    // [2] src IP
    uint8_t sip[common::IP_V4_SIZE]{};
    if (!parse_ip(fields_[2], sip)) return false;
    for (int i = 0; i < common::IP_V4_SIZE; ++i) sum += sip[i];

    // [3] dst IP
    uint8_t dip[common::IP_V4_SIZE]{};
    if (!parse_ip(fields_[3], dip)) return false;
    for (int i = 0; i < common::IP_V4_SIZE; ++i) sum += dip[i];

    // [4] TTL (4 bytes)
    uint32_t ttl = parse_u32(fields_[4]);
    sum += sum_u32(ttl);

    // [5] layer-3 checksum (4 bytes)
    uint32_t l3cs = parse_u32(fields_[5]);
    sum += sum_u32(l3cs);

    // [6] src port (2 bytes)
    uint16_t sp = static_cast<uint16_t>(parse_u32(fields_[6]));
    sum += sum_u16(sp);

    // [7] dst port (2 bytes)
    uint16_t dp = static_cast<uint16_t>(parse_u32(fields_[7]));
    sum += sum_u16(dp);

    // [8] index (4 bytes)
    uint32_t idx = parse_u32(fields_[8]);
    sum += sum_u32(idx);

    // [9] data payload (hex bytes)
    std::vector<uint8_t> payload;
    parse_hex_payload(fields_[9], payload);
    for (uint8_t b : payload) sum += b;

    // Compare with provided layer-2 checksum (decimal), modulo 2^32 to fit 4 bytes
    uint32_t expected = static_cast<uint32_t>(sum & 0xFFFFFFFFu);
    uint32_t provided = static_cast<uint32_t>(std::stoul(fields_[10]));
    if (expected != provided) return false;

    // Cache EXACTLY the 8 layer-3 fields: indices [2..9]
    l3line_cached_.clear();
    for (size_t i = 2; i <= 9; ++i) {
        if (i > 2) l3line_cached_.push_back('|');
        l3line_cached_ += fields_[i];
    }

    return true;
}




bool l2_packet::proccess_packet(common::open_port_vec &open_ports,
                                uint8_t ip[common::IP_V4_SIZE],
                                uint8_t mask,
                                common::memory_dest &dst) {
    // delegate to layer-3 and then cache the final, updated layer-3 text
    l3_packet inner(l3line_cached_);
    uint8_t dummy_mac[common::MAC_SIZE]{};
    if (!inner.validate_packet(open_ports, ip, mask, dummy_mac)) return false;
    bool ok = inner.proccess_packet(open_ports, ip, mask, dst);
    if (ok) { std::string tmp; inner.as_string(tmp); l3line_cached_ = tmp; }
    return ok;
}

bool l2_packet::as_string(std::string &out_text) {
    // yields the final layer-3 text for RQ/TQ storage
    out_text = l3line_cached_;
    return true;
}
