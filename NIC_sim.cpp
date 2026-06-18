#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <iomanip>

#include "NIC_sim.hpp"
#include "L2.h"
#include "L3.h"
#include "L4.h"

using namespace std;

static vector<string> split_lines_file(const string& file_path) {
    ifstream in(file_path);
    vector<string> lines;
    string s;
    while (getline(in, s)) {
        if (!s.empty() && s.back() == '\r') s.pop_back();
        if (!s.empty()) lines.push_back(s);
    }
    return lines;
}

static vector<string> split_by_comma(const string& text) {
    vector<string> out;
    string cur;
    for (char c : text) {
        if (c == ',') { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    return out;
}

nic_sim::nic_sim(const std::string &param_file) {
    load_params(param_file);
}

void nic_sim::load_params(const std::string& cfg_path) {
    ifstream in(cfg_path);
    string mac_line, ip_mask_line;
    if (!getline(in, mac_line)) return;
    if (!getline(in, ip_mask_line)) return;

    // Decode MAC: "aa:bb:cc:dd:ee:ff"
    {
        std::istringstream iss(mac_line);
        std::string byte; int i = 0;
        while (std::getline(iss, byte, ':') && i < common::MAC_SIZE) {
            unsigned int v = 0;
            std::istringstream bx(byte);
            bx >> std::hex >> v;
            mac[i++] = static_cast<uint8_t>(v & 0xFF);
        }
    }

    // Decode IP/Mask: "a.b.c.d/m"
    {
        auto slash = ip_mask_line.find('/');
        std::string ip_s = ip_mask_line.substr(0, slash);
        mask = static_cast<uint8_t>(std::stoi(ip_mask_line.substr(slash+1)));
        std::istringstream iss(ip_s);
        std::string part; int i = 0;
        while (std::getline(iss, part, '.') && i < common::IP_V4_SIZE) {
            int v = std::stoi(part);
            ip[i++] = static_cast<uint8_t>(v);
        }
    }

    // Remaining lines: "src_prt:x, dst_port:y"
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto parts = split_by_comma(line);
        uint16_t src = static_cast<uint16_t>(std::stoul(parts[0].substr(parts[0].find(':')+1)));
        uint16_t dst = static_cast<uint16_t>(std::stoul(parts[1].substr(parts[1].find(':')+1)));
        common::open_port op{};
        op.src_prt = src;
        op.dst_prt = dst;
        std::fill(std::begin(op.data), std::end(op.data), 0);
        open_ports.push_back(op);
    }
}

bool nic_sim::is_ip_in_local_net(const uint8_t ip_bytes[common::IP_V4_SIZE]) const {
    auto to_u32 = [](const uint8_t b[common::IP_V4_SIZE]) {
        return (uint32_t(b[0])<<24) | (uint32_t(b[1])<<16) | (uint32_t(b[2])<<8) | uint32_t(b[3]);
    };
    uint32_t a = to_u32(ip);
    uint32_t b = to_u32(ip_bytes);

    // checks the mask /0 means no local subnet
    if (mask == 0) return false;

    uint32_t m = (mask == 32) ? 0xFFFFFFFFu : (~0u << (32 - mask));
    return (a & m) == (b & m);
}

std::string nic_sim::ip_to_string(const uint8_t ip_bytes[common::IP_V4_SIZE]) const {
    std::ostringstream os;
    os << int(ip_bytes[0]) << "." << int(ip_bytes[1]) << "."
       << int(ip_bytes[2]) << "." << int(ip_bytes[3]);
    return os.str();
}

std::string nic_sim::mac_to_string(const uint8_t mac_bytes[common::MAC_SIZE]) const {
    std::ostringstream os;
    for (int i = 0; i < common::MAC_SIZE; ++i) {
        if (i) os << ":";
        os << std::hex << std::nouppercase
           << std::setw(2) << std::setfill('0')
           << int(mac_bytes[i]);
    }
    return os.str();
}

generic_packet* nic_sim::packet_factory(const std::string &raw_line) {
    size_t bars = std::count(raw_line.begin(), raw_line.end(), '|');
    if (bars >= 9) return new l2_packet(raw_line);
    if (bars == 7)  return new l3_packet(raw_line);
    if (bars == 3)  return new l4_packet(raw_line);
    return nullptr;
}

void nic_sim::nic_flow(const std::string &trace_path) {
    auto lines = split_lines_file(trace_path);
    for (auto& line : lines) {
        std::unique_ptr<generic_packet> pkt(packet_factory(line));
        if (!pkt) continue;
        if (!pkt->validate_packet(open_ports, ip, mask, mac)) continue;
        common::memory_dest dst;
        if (!pkt->proccess_packet(open_ports, ip, mask, dst)) continue;

        if (dst == common::RQ || dst == common::TQ) {
            std::string s;
            pkt->as_string(s);
            if (dst == common::RQ) rq.push_back(s);
            else                   tq.push_back(s);
        }
        // LOCAL_DRAM writes happen inside proccess_packet
    }
}

void nic_sim::nic_print_results() const {
    // LOCAL DRAM:
    std::cout << "LOCAL DRAM:\n";
    for (const auto& op : open_ports) {
        std::cout << op.src_prt << " " << op.dst_prt << ": ";
        for (int i = 0; i < 64; ++i) {
            std::cout << std::hex << std::nouppercase
                      << std::setw(2) << std::setfill('0')
                      << (int)(unsigned char)op.data[i];
            if (i != 63) std::cout << " ";
        }
        std::cout << std::dec << "\n";
    }

    // one blank line after DRAM section
    std::cout << "\n";

    // RQ (always print)
    std::cout << "RQ:\n";
    for (const auto& s : rq) std::cout << s << "\n";
    std::cout << "\n";

    // TQ
    std::cout << "TQ:\n";
    for (const auto& s : tq) std::cout << s << "\n";
}
