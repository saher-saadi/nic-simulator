#include <sstream>
#include <algorithm>
#include <numeric>
#include <cstdint>
#include <vector>
#include <string>
#include <cstdio>

#include "L3.h"
#include "L4.h"


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

// normalize "hex bytes" text to lowercase, 2-digit, single-space separated
static std::string normalize_hex_bytes(const std::string& s) {
    std::istringstream iss(s);
    std::string tok, out;
    bool first = true;
    while (iss >> tok) {
        unsigned int v = 0;
        std::istringstream bx(tok);
        bx >> std::hex >> v;
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", (v & 0xFF));
        if (!first) out.push_back(' ');
        out += buf;
        first = false;
    }
    return out;
}

l3_packet::l3_packet(const std::string& line) : raw_(line), fields_(split_by_bar(line)) {}

bool l3_packet::parse_ip(const std::string& ip_str, uint8_t out[common::IP_V4_SIZE]) {
    std::istringstream iss(ip_str);
    std::string part; int idx = 0;
    while (std::getline(iss, part, '.')) {
        if (idx >= common::IP_V4_SIZE) return false;
        int v = std::stoi(part);
        if (v < 0 || v > 255) return false;
        out[idx++] = static_cast<uint8_t>(v);
    }
    return idx == common::IP_V4_SIZE;
}

// member versions to match layer-3.h
uint32_t l3_packet::parse_u32(const std::string& text) { return static_cast<uint32_t>(std::stoul(text)); }

bool l3_packet::ip_equal(const uint8_t lhs[common::IP_V4_SIZE],
                         const uint8_t rhs[common::IP_V4_SIZE]) {
    for (int i = 0; i < common::IP_V4_SIZE; ++i) if (lhs[i] != rhs[i]) return false;
    return true;
}

bool l3_packet::parse_hex_payload(const std::string& s, std::vector<uint8_t>& out) {
    std::istringstream iss(s);
    std::string byte;
    while (iss >> byte) {
        unsigned int v = 0;
        std::istringstream bx(byte);
        bx >> std::hex >> v;
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    }
    return true;
}

// Byte-sum checksum (IP octets + TTL bytes + ports bytes + index bytes + data payload bytes)
uint64_t l3_packet::compute_l3_checksum(const std::vector<std::string>& f) {

    auto sum_ip = [&](const std::string& ip) {
        uint64_t s = 0; std::istringstream iss(ip); std::string p;
        while (std::getline(iss, p, '.')) s += std::stoul(p); // octet values
        return s;
    };
    uint32_t ttlv = static_cast<uint32_t>(std::stoul(f[2]));
    uint64_t sum = sum_ip(f[0]) + sum_ip(f[1])
             + ((ttlv) & 0xFFu) + ((ttlv >> 8) & 0xFFu)
             + ((ttlv >> 16) & 0xFFu) + ((ttlv >> 24) & 0xFFu);

    // skip f[3] (checksum)
    // for ports/index we apply byte sums of their 16/32-bit encodings
    auto sum_u16_bytes = [](uint32_t v) { return (v & 0xFFu) + ((v >> 8) & 0xFFu); };
    auto sum_u32_bytes = [](uint32_t v) { return (v & 0xFFu) + ((v >> 8) & 0xFFu) + ((v >> 16) & 0xFFu) + ((v >> 24) & 0xFFu); };
    sum += sum_u16_bytes(std::stoul(f[4]));
    sum += sum_u16_bytes(std::stoul(f[5]));
    sum += sum_u32_bytes(std::stoul(f[6]));
    std::vector<uint8_t> payload;
    parse_hex_payload(f[7], payload);
    for (auto b : payload) sum += b;
    return sum;
}

static uint32_t sum_bytes_u32(uint32_t v) {
    return (v & 0xFFu) + ((v >> 8) & 0xFFu) + ((v >> 16) & 0xFFu) + ((v >> 24) & 0xFFu);
}
static uint32_t sum_ip_octets(const uint8_t ip[common::IP_V4_SIZE]) {
    return uint32_t(ip[0]) + uint32_t(ip[1]) + uint32_t(ip[2]) + uint32_t(ip[3]);
}

bool l3_packet::validate_packet(common::open_port_vec ,
                                uint8_t [common::IP_V4_SIZE],
                                uint8_t ,
                                uint8_t [common::MAC_SIZE]) {
    if (fields_.size() != 8) return false;

    // TTL must be > 0
    uint32_t ttl = parse_u32(fields_[2]);
    if (ttl == 0) return false;

    // Decode IPs (also protects checksum calc)
    uint8_t sip[common::IP_V4_SIZE]{}, dip[common::IP_V4_SIZE]{};
    if (!parse_ip(fields_[0], sip) || !parse_ip(fields_[1], dip)) return false;

    // Range check
    unsigned long sport_ul = std::stoul(fields_[4]);
    unsigned long dport_ul = std::stoul(fields_[5]);
    unsigned long index_ul = std::stoul(fields_[6]);
    if (sport_ul > 65535ul || dport_ul > 65535ul || index_ul > 63ul) return false;

    // Checksum (byte-sum model)
    uint64_t expect = compute_l3_checksum(fields_);
    uint32_t given  = parse_u32(fields_[3]);
    if (expect != given) return false;

    return true;
}

bool l3_packet::proccess_packet(common::open_port_vec &open_ports,
                                uint8_t ip[common::IP_V4_SIZE],
                                uint8_t mask,
                                common::memory_dest &dst) {
    // Decode src/dst IPs
    uint8_t sip[common::IP_V4_SIZE]{}, dip[common::IP_V4_SIZE]{};
    if (!parse_ip(fields_[0], sip) || !parse_ip(fields_[1], dip)) return false;

    //network interface-local subnet
    auto to_u32 = [](const uint8_t b[common::IP_V4_SIZE]) {
        return (uint32_t(b[0])<<24) | (uint32_t(b[1])<<16) | (uint32_t(b[2])<<8) | uint32_t(b[3]);
    };
    auto is_local = [&](const uint8_t other[common::IP_V4_SIZE]) {
        uint32_t nic = to_u32(ip), oth = to_u32(other);
        if (mask == 32) return nic == oth;   // /32: only exact IP
        uint32_t m = (mask == 0) ? 0u : (~0u) << (32 - mask);  
        // /0 => m=0 everything matches
        return (nic & m) == (oth & m);
    };

    // To network interface IP -> DRAM via layer-4 (NO TTL/CS change; keep original data payload)
    if (ip_equal(dip, ip)) {
        std::string l4line = fields_[4] + "|" + fields_[5] + "|" + fields_[6] + "|" + fields_[7];
        l4_packet seg(l4line);
        uint8_t dummy_mac[common::MAC_SIZE]{};
        if (!seg.validate_packet(open_ports, ip, mask, dummy_mac)) return false;
        common::memory_dest inner_dst;
        if (!seg.proccess_packet(open_ports, ip, mask, inner_dst)) return false;
        dst = inner_dst; // LOCAL_DRAM
        return true;
    }

    //Forwarding decisions
    bool src_local = is_local(sip);
    bool dst_local = is_local(dip);

    // Drop local→local frames
    if (src_local && dst_local) {
        return false;
    }

    uint32_t ttl = parse_u32(fields_[2]);
    if (ttl <= 1u) {
        return false; // would hit 0 -> drop
    }

    uint32_t oldcs = parse_u32(fields_[3]);
    int32_t  delta_ttl = int32_t(sum_bytes_u32(ttl - 1u)) - int32_t(sum_bytes_u32(ttl));

    std::vector<std::string> f = fields_; // start from original fields
    f[2] = std::to_string(ttl - 1u);      // TTL-1 (applies to all forwarding outcomes)

    if (src_local && !dst_local) {
        // local → external (TQ): NAT src IP; adjust checksum by TTL delta + IP-sum delta
        uint32_t oldsrcsum = sum_ip_octets(sip);
        uint32_t nicsum    = sum_ip_octets(ip);
        uint32_t newcs     = static_cast<uint32_t>( int64_t(oldcs)
                                 + int64_t(delta_ttl)
                                 - int64_t(oldsrcsum)
                                 + int64_t(nicsum) );
        f[0] = std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
               std::to_string(ip[2]) + "." + std::to_string(ip[3]);
        f[3] = std::to_string(newcs);
        f[7] = normalize_hex_bytes(f[7]);   // normalize data payload for TQ

        raw_ = f[0] + "|" + f[1] + "|" + f[2] + "|" + f[3] + "|" +
               f[4] + "|" + f[5] + "|" + f[6] + "|" + f[7];
        dst = common::TQ;
        return true;
    }

    if (!src_local && !dst_local) {
        // external → external (transit): TQ, TTL delta only; normalize data payload
        uint32_t newcs = static_cast<uint32_t>(int64_t(oldcs) + int64_t(delta_ttl));
        f[3] = std::to_string(newcs);
        f[7] = normalize_hex_bytes(f[7]);

        raw_ = f[0] + "|" + f[1] + "|" + f[2] + "|" + f[3] + "|" +
               f[4] + "|" + f[5] + "|" + f[6] + "|" + f[7];
        dst = common::TQ;
        return true;
    }

    // external → local : RQ (TTL-1, checksum adjusted by TTL delta; normalize data payload formatting)
    {
        uint32_t newcs = static_cast<uint32_t>(int64_t(oldcs) + int64_t(delta_ttl));
        f[3] = std::to_string(newcs);
        f[7] = normalize_hex_bytes(f[7]);

        raw_ = f[0] + "|" + f[1] + "|" + f[2] + "|" + f[3] + "|" +
               f[4] + "|" + f[5] + "|" + f[6] + "|" + f[7];
        dst = common::RQ;
        return true;
    }
}

bool l3_packet::as_string(std::string &out_text) {
    out_text = raw_;
    return true;
}
