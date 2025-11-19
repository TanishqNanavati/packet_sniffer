# TCP/IP Packet Sniffer (Raw Sockets, C, Linux)

A lightweight packet-sniffer written entirely in **C**, using **raw sockets**.  
It captures **raw Ethernet frames** directly from a Linux network interface and decodes:

- Ethernet Header  
- ARP  
- IPv4  
- TCP  
- UDP  
- ICMP  

No external libraries — only Linux system calls.

---

## 🚀 Features

✔ Capture raw packets using **AF_PACKET**  
✔ Decode Ethernet/IPv4/TCP/UDP/ICMP headers  
✔ Promiscuous mode support  
✔ Filter system (e.g., only TCP/UDP, source host, ports, etc.)  
✔ ANSI-colored terminal output  
✔ Clean modular architecture (`sniffer.c`, `parser.c`, `util.c`, etc.)  
✔ Simple to extend

---

## 📦 Build Instructions (CMake)

```bash
mkdir build
cd build
cmake ..
make


Command:
sudo ./sniffer -i <interface> [-f "filter"] [-c count]

EX:

Capture all packets from eth0
sudo ./sniffer -i eth0

Capture only TCP Packets
sudo ./sniffer -i eth0 -f "tcp"

Capture only 20 packets:
sudo ./sniffer -i eth0 -c 20


Capture specific packet from specific src and host
sudo ./sniffer -i eth0 -f "udp and src host 1.2.3.4"


