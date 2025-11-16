#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Ethernet Header
struct EtherHeader{
    uint8_t src[6];
    uint8_t dest[6];
    uint16_t ethertype;  // byte order or network order
}__attribute__((packed));


// ARP Header Format
struct ARPHeader{
    uint16_t htype;   // hardware type
    uint16_t ptype;   // protocol type
    uint8_t hlen;     // hardware address length
    uint8_t plen;     // protocol address length
    uint16_t oper;    // operation type
    uint8_t sha[6];   // sender hardware address (MAC)
    uint8_t spa[4];   // sender protocol address (IP)
    uint8_t tha[6];   // target hardware address (MAC)
    uint8_t tpa[4];   // target protocol address (IP)
}__attribute__((packed));

// IPv4 header
struct IPv4Header{
    uint8_t ver_ihl;       // higher nibble version,lower nibble header len
    uint8_t tos;           // type of service
    uint16_t tot_len;      // total length of packet(header + data)
    uint16_t id;           // fragmentation id
    uint16_t frag_off;     // 3 flag bits + 13bit frag offset 
    uint8_t ttl;           // time to live
    uint8_t protocol;      // type of protocol (Ex:TCP,UDP,ICMP,OSPF)
    uint16_t checksum;     // Error Checksum
    uint32_t saddr;        // src IP address
    uint32_t daddr;        // dest IP address
}__attribute__((packed));

// TCP Header
struct TCPHeader{
    uint16_t source;          // source address
    uint16_t dest;            // dest address
    uint32_t seq;             // sequence number
    uint32_t ack_seq;         // acknowledgement
    uint16_t doff_res_flags;  // data offset + reserved_bits + flags
    uint16_t window;          // window size
    uint16_t check;           // checksum
    uint16_t urg_ptr;         // points to urgent packet
}__attribute__((packed));

// UDP Header
struct UDPHeader{
    uint16_t source;         // source address
    uint16_t dest;           // dest address
    uint16_t checksum;       // Error checksum
    uint16_t len;            // Total len (header + Payload)
}__attribute__((packed));

// ICMP Header

struct ICMPHeader{
    uint8_t type;             // Type of Message
    uint8_t code;             // details about packet
    uint16_t checksum;        // Error checksum
    uint32_t rest;            // Type specific data
}__attribute__((packed));


// print functions

void print_eth(const uint8_t* pkt,size_t size);
void print_arp(const uint8_t* pkt,size_t size);
void print_ip(const uint8_t* pkt,size_t size);
void print_tcp(const uint8_t* pkt,size_t size,size_t ip_header_len);
void print_udp(const uint8_t* pkt,size_t size,size_t ip_header_len);
void print_icmp(const uint8_t* pkt,size_t size,size_t ip_header_len);

typedef struct {
    int match_tcp;
    int match_udp;
    int match_icmp;
    int match_arp;

    int has_src_ip;
    uint32_t src_ip; // network order

    int has_dst_ip;
    uint32_t dst_ip; 

    int has_src_port;
    uint16_t src_port; // network order

    int has_dst_port;
    uint16_t dst_port; // network order
}SimpleFilter;

void parse_filter_expression(const char* expr,SimpleFilter* out);
int packet_matches_filter(const uint8_t* pkt,size_t size,const SimpleFilter* f);

#ifdef __cplusplus
}
#endif

#endif // PARSER_H
