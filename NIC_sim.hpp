#ifndef __NIC_SIM_H__
#define __NIC_SIM_H__

#include <vector>
#include <string>
#include <cstdint>
#include "common.hpp"
#include "packets.hpp"


class nic_sim {
public:
    explicit nic_sim(const std::string& param_file);

    void nic_flow(const std::string& packet_file);

    void nic_print_results() const;

    generic_packet* packet_factory(const std::string& line);


    // memory areas (visible so packets can push into them)

    common::open_port_vec open_ports;   // 64B per open (src,dst)

    std::vector<std::string> rq;        // receive queue (L3 string form)

    std::vector<std::string> tq;        // transmit queue (L3 string form)


    // NIC identity/config

    uint8_t ip[common::IP_V4_SIZE]{};   // NIC IPv4

    uint8_t mac[common::MAC_SIZE]{};    // NIC MAC

    uint8_t mask = 0;                   // CIDR mask bits (0–32)


    // helpers used by L3

    bool is_ip_in_local_net(const uint8_t ip_bytes[common::IP_V4_SIZE]) const;

    std::string ip_to_string(const uint8_t ip_bytes[common::IP_V4_SIZE]) const;

    std::string mac_to_string(const uint8_t mac_bytes[common::MAC_SIZE]) const;


private:

    void load_params(const std::string& param_file);

};


#endif // __NIC_SIM_H_
