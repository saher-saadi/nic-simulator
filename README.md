# NIC Simulator

A C++ simulator of a **Network Interface Card (NIC)** that ingests network packets, validates them, updates their headers, and routes them to the correct destination — modeled around a layered protocol stack (L2 / L3 / L4) and built on inheritance and polymorphism.

> Academic project — *Introduction to Software Systems (044101)*, Andrew & Erna Viterbi Faculty of Electrical & Computer Engineering, Technion.

---

## What this project demonstrates

- **Object-oriented design** — an abstract base class (`generic_packet`) with a polymorphic hierarchy of packet types
- **Factory design pattern** — runtime construction of the correct packet object from a raw text line
- **Layered networking model** — independent parsing and validation of L2 (data link), L3 (network), and L4 (transport) layers
- **Packet routing logic** — receive, transmit, transit, and local-delivery decisions
- **Protocol mechanics** — checksum verification, TTL decrement and drop, CIDR subnet matching, and source-IP rewriting (NAT-style) on egress
- **Manual memory management** — dynamic allocation with a clean ownership model, verified leak-free with Valgrind

---

## Overview

The simulator emulates a NIC that bridges a **local network** to the **outside world**. The NIC is configured with an IP address, a subnet mask, a MAC address, and a set of open connections. For every incoming packet it decides — based on the packet's layer and its source/destination addresses — whether the packet should be:

- written to the **Receive Queue (RQ)** — traffic entering the local network,
- written to the **Transmit Queue (TQ)** — traffic leaving the local network or transiting through it, or
- delivered to **Local DRAM** — traffic addressed to the NIC itself, written into the buffer of the matching open connection.

The program reads two input files (a parameter file and a packet trace), processes every packet, and prints the resulting contents of all three memory regions.

---

## Architecture

All packet types derive from a single abstract interface, so the NIC can process any packet through the same three calls without knowing its concrete type:

```
generic_packet  (abstract base — pure virtual interface)
│   • validate_packet()   — is the packet well-formed and valid?
│   • proccess_packet()   — update the packet, return its memory destination
│   • as_string()         — serialize back to text for RQ / TQ
│
├── l2_packet   (data link)  → strips L2, delegates to L3
├── l3_packet   (network)    → routing, TTL, checksum; delegates to L4 when local
└── l4_packet   (transport)  → writes payload into the open connection's buffer
```

A **factory** in `nic_sim` inspects each raw line and instantiates the right object, returning a pointer to the base class. This keeps creation logic in one place and makes the design easy to extend with new packet types.

Higher layers process a packet by **stripping their own header and handing the inner payload to the next layer down** (L2 → L3 → L4), mirroring how a real protocol stack peels encapsulation.

---

## Packet layers

| Layer | Role | Key fields |
|-------|------|-----------|
| **L2** | Data link | source MAC, destination MAC, checksum |
| **L3** | Network | source IP, destination IP, TTL, checksum |
| **L4** | Transport | source port, destination port, memory index, payload |

Fields in a packet line are separated by `|`. The factory distinguishes packet types by structure, so a single trace file can mix L2, L3, and L4 packets.

---

## Routing logic (L3)

For each valid L3 packet (TTL > 0 and checksum verified), the NIC applies the following rules:

| Source | Destination | Action | Goes to |
|--------|-------------|--------|---------|
| external | local | decrement TTL, update checksum | **RQ** |
| local | external | rewrite source IP to NIC, decrement TTL, update checksum | **TQ** |
| external | external | decrement TTL, update checksum (transit) | **TQ** |
| any | the NIC itself | strip L3, process L4 payload | **Local DRAM** |
| local | local | drop | — |

Packets whose TTL would reach zero are dropped, preventing infinite circulation.

---

## Build

Requires a C++11-capable compiler (`g++`) and `make`.

```bash
make            # builds the executable: nic_sim.exe
make clean      # removes object files and the executable
```

The build uses `-Wall -Wextra -std=c++11`.

---

## Usage

```bash
./nic_sim.exe <param_file> <packet_file>
```

- `<param_file>` — NIC configuration (MAC, IP/mask, open connections)
- `<packet_file>` — newline-separated packets to process

To check for memory leaks:

```bash
valgrind --leak-check=full ./nic_sim.exe <param_file> <packet_file>
```

---

## Input formats

**Parameter file**

```
aa:bb:cc:dd:ee:ff          # NIC MAC address (hex)
192.168.1.10/24            # NIC IP address / CIDR mask
src_prt:2500, dst_prt:2000 # an open connection (one per line)
src_prt:4000, dst_prt:5000
```

**Packet file** — one packet per line. Fields are `|`-separated; payload bytes are space-separated hex. A full L2 packet, for example, carries the L2 MAC headers, the encapsulated L3/L4 fields, the payload, and a trailing checksum:

```
A1:12:57:9F:00:01|C2:02:01:90:10:02|4.52.123.8|4.52.123.6|23|1036|2500|2000|0|DD 00 ... 00|1963
```

*(Illustrative format from the project specification.)*

---

## Output

The program prints the three memory regions in order: **Local DRAM** (per open connection, as a 64-byte buffer in hex), then **RQ**, then **TQ**.

---

## Tests

The `tests/` folder contains three sample scenarios, each with a parameter file, a packet trace, and the expected output. To run a test and compare against the expected result:

```bash
./nic_sim.exe tests/test0_param.in tests/test0_packets.in | diff - tests/test0_res.out
```

No output from `diff` means the result matches. All included tests pass.

---

## Project structure

```
.
├── main.cpp        # entry point: parses args, runs the simulation
├── NIC_sim.hpp     # NIC class: config, factory, queues, run loop
├── NIC_sim.cpp
├── packets.hpp     # generic_packet abstract base + shared helper
├── common.hpp      # shared constants, memory_dest enum, open_port struct
├── L2.h / L2.cpp   # data-link packet
├── L3.h / L3.cpp   # network packet (routing core)
├── L4.h / L4.cpp   # transport packet
├── Makefile
└── tests/          # sample inputs and expected outputs
    ├── test0_param.in / test0_packets.in / test0_res.out
    ├── test1_param.in / test1_packets.in / test1_res.out
    └── test2_param.in / test2_packets.in / test2_res.out
```

---

## Notes

This project was implemented in C++ with an emphasis on two graded objectives: **correctness** (filtering, updating, and routing packets exactly as specified) and **resource management** (no memory leaks). The polymorphic design and factory pattern were chosen to keep the per-layer logic isolated and the system open to extension.
