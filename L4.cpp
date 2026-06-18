#include <sstream>
#include <algorithm>

#include "L4.h"

// Break a text by '|' to pieces
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

// Build layer-4 packet from the input line by splitting to fields
l4_packet::l4_packet(const std::string& line) : raw_(line), fields_(split_by_bar(line)) {}

// Turn text to unsigned 32-bit integer
uint32_t l4_packet::parse_u32(const std::string& s) { return static_cast<uint32_t>(std::stoul(s)); }

// Decode a hex pieces in flexible formats like "1a", "0x1A", "1a,"
static inline bool parse_hex_token_relaxed(const std::string& tok, unsigned& out) {
    // Accept: "1a", "1A", "0x1a", "0X1A", and allow trailing comma "1a,"
    size_t start = 0, end = tok.size();
    if (end == 0) return false;
    if (tok[end-1] == ',') --end;
    if (end - start >= 2 && tok[start] == '0' && (tok[start+1] == 'x' || tok[start+1] == 'X')) start += 2;
    if (start >= end) return false;

    out = 0;
    for (size_t i = start; i < end; ++i) {
        char c = tok[i];
        unsigned d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10 + (c - 'A');
        else return false;
        out = (out << 4) | d;
    }
    return true;
}

// Decode a hex data payload text to a byte array
bool l4_packet::parse_hex_payload(const std::string& hex, std::vector<uint8_t>& bytes) {
    std::istringstream iss(hex);
    std::string byte;
    while (iss >> byte) {
        unsigned v = 0;
        if (!parse_hex_token_relaxed(byte, v)) {
            unsigned int vv = 0;
            std::istringstream bx(byte);
            bx >> std::hex >> vv;
            v = vv;
        }
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
    }
    return true;
}

bool l4_packet::validate_packet(common::open_port_vec ,
                                uint8_t [common::IP_V4_SIZE],
                                uint8_t ,
                                uint8_t [common::MAC_SIZE]) {
    // For layer-4 we just check the field count and that index fits [0,63]
    if (fields_.size() != 4) return false;
    uint32_t idx = parse_u32(fields_[2]);
    return idx < 64;
}

bool l4_packet::proccess_packet(common::open_port_vec &open_ports,
                                uint8_t [common::IP_V4_SIZE],
                                uint8_t ,
                                common::memory_dest &dst) {
    // Check there is an open connection (src,dst) and write bytes to its 64B buffer starting at index
    if (fields_.size() != 4) return false;
    uint16_t src  = static_cast<uint16_t>(parse_u32(fields_[0]));
    uint16_t dstp = static_cast<uint16_t>(parse_u32(fields_[1]));
    uint32_t idx  = parse_u32(fields_[2]);

    auto it = std::find_if(open_ports.begin(), open_ports.end(), [&](const common::open_port& op) {
        return op.src_prt == src && op.dst_prt == dstp;
    });
    if (it == open_ports.end()) return false;

    std::vector<uint8_t> payload;
    parse_hex_payload(fields_[3], payload);

    for (size_t i = 0; i < payload.size(); ++i) {
        size_t pos = idx + i;
        if (pos >= sizeof(it->data)) break;
        it->data[pos] = static_cast<char>(payload[i]);
    }

    dst = common::LOCAL_DRAM;
    return true;
}

bool l4_packet::as_string(std::string &out_text) {
    out_text = raw_;
    return true;
}
