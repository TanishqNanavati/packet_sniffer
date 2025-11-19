#include"parser.h"
#include"util.h"
#include<stdio.h>
#include<string.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<ctype.h>
#include<stdlib.h>

typedef struct EthHeader EthHeader;
typedef struct IPv4Header IPv4Header;
typedef struct ARPHeader ARPHeader;
typedef struct TCPHeader TCPHeader;
typedef struct UDPHeader UDPHeader;
typedef struct ICMPHeader ICMPHeader;


static int str_iequal(const char* a,const char* b){
    while(*a && *b){
        if(tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }

    return *a == *b;
}

void print_eth(const uint8_t* pkt,size_t size){
    if(size < sizeof(EthHeader)) return;

    const EthHeader* eth = (const EthHeader*)pkt;
    uint16_t et = ntohs(eth->ethertype);
    char src[32],dst[32];
    mac_to_string(eth->src,src,sizeof(src));
    mac_to_string(eth->dest,dst,sizeof(dst));

    printf("%s%sEthernet : %s -> %s  Ethertype : 0x%04x%s\n",COLOR_WHITE,COLOR_BOLD,src,dst,et,COLOR_RESET);
}

void print_arp(const uint8_t* pkt,size_t size){
    if(size < (sizeof(ARPHeader) + sizeof(EthHeader))) return;

    const ARPHeader* arp = (const ARPHeader*)(pkt + sizeof(EthHeader));
    char sha[32];
    mac_to_string(arp->sha,sha,sizeof(sha));
    printf("%s%sARP : op = %u sha = %s spa = %u.%u.%u.%u%s\n",COLOR_MAGENTA,COLOR_BOLD,(unsigned)ntohs(arp->oper),sha,(unsigned)arp->spa[0],(unsigned)arp->spa[1],(unsigned)arp->spa[2],(unsigned)arp->spa[3],COLOR_RESET);
}

void print_ip(const uint8_t* pkt,size_t size){
    if(size < (sizeof(EthHeader) + sizeof(IPv4Header))) return;

    const IPv4Header * ip = (const IPv4Header*)(pkt + sizeof(EthHeader));
    uint8_t version = ip->ver_ihl >> 4;
    uint8_t ihl = (ip->ver_ihl & 0x0F)*4;

    if(size < sizeof(EthHeader) + ihl) return;

    char src[INET_ADDRSTRLEN],dst[INET_ADDRSTRLEN];
    ip_to_string(ip->saddr,src,sizeof(src));
    ip_to_string(ip->daddr,dst,sizeof(dst));

    printf("%s%sTPv4 : %s -> %s  ver = %u ihl = %u ttl = %u proto = %u%s\n",COLOR_WHITE,COLOR_BOLD,src,dst,(unsigned)version,(unsigned)ihl,(unsigned)ip->ttl,(unsigned)ip->protocol,COLOR_RESET);

}

void print_tcp(const uint8_t* pkt,size_t size,size_t ip_header_len){

    size_t base = sizeof(EthHeader) + ip_header_len;

    if(size < (base + sizeof(TCPHeader))) return;

    const TCPHeader* tcp = (const TCPHeader*)(pkt + base);
    uint16_t sport = ntohs(tcp->source);
    uint16_t dport = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack_seq);
    uint8_t data_offset = (ntohs(tcp->doff_res_flags) >> 12)*4;
    uint16_t flags = ntohs(tcp->doff_res_flags) & 0x01FF;  // lower 9 bits --> 0x01FF  = 0000 0001 1111 1111 (binary)

    printf("%s%STCP : %u -> %u seq = %u ack = %u data_offset = %u flags = [",COLOR_GREEN,COLOR_BOLD,(unsigned)sport,(unsigned)dport,(unsigned)seq,(unsigned)ack,(unsigned)data_offset);
    
    if(flags & 0x002) printf("SYN ");
    if(flags & 0x010) printf("ACK ");
    if(flags & 0x001) printf("FIN ");
    if(flags & 0x004) printf("RST ");
    if(flags & 0x008) printf("PSH ");
    if(flags & 0x020) printf("URG ");

    // TCP FLag
    //     CWR ECE URG ACK PSH RST SYN FIN
    // bit8 bit7 bit6 bit5 bit4 bit3 bit2 bit1 bit0

    // EX :
    // flags = 0b000000010   (SYN set)
    // flags = 0b000100010   (ACK + SYN set)
    // flags = 0b000001001   (PSH + FIN set)


    printf("]%s\n",COLOR_RESET);
}

void print_udp(const uint8_t* pkt,size_t size,size_t ip_header_len){
    size_t base = sizeof(EthHeader) + ip_header_len;

    if(size < (base + sizeof(UDPHeader))) return;

    const UDPHeader* udp = (const UDPHeader*)(pkt + base);

    uint16_t sport = ntohs(udp->source);
    uint16_t dport = ntohs(udp->dest);
    uint16_t len = ntohs(udp->len);

    printf("%s%sUDP : %u -> %u length = %u%s\n",COLOR_CYAN,COLOR_BOLD,(unsigned)sport,(unsigned)dport,(unsigned)len,COLOR_RESET);
}

void print_icmp(const uint8_t* pkt,size_t size,size_t ip_header_len){
    size_t base = sizeof(EthHeader) + ip_header_len;

    if(size < (base) + sizeof(ICMPHeader)) return;

    const ICMPHeader* icmp = (const ICMPHeader*)(pkt + base);
    printf("%s%sICMP : type = %u code = %u%s\n",COLOR_YELLOW,COLOR_BOLD,(unsigned)icmp->type,(unsigned)icmp->code,COLOR_RESET);
}


void parse_filter_expression(const char* expr, SimpleFilter* out) {
    if (!out) return;
    memset(out, 0, sizeof(SimpleFilter));
    if (!expr) return;
    char *buf = strdup(expr);
    if (!buf) return;
    char *saveptr = NULL;
    char *tok = NULL;
    for (tok = strtok_r(buf, " \t", &saveptr); tok; tok = strtok_r(NULL, " \t", &saveptr)) {
        if (str_iequal(tok, "and")) continue;
        if (str_iequal(tok, "tcp")) { out->match_tcp = 1; continue; }
        if (str_iequal(tok, "udp")) { out->match_udp = 1; continue; }
        if (str_iequal(tok, "icmp")) { out->match_icmp = 1; continue; }
        if (str_iequal(tok, "arp")) { out->match_arp = 1; continue; }
        if (str_iequal(tok, "src")) {
            char *next = strtok_r(NULL, " \t", &saveptr);
            if (!next) break;
            if (str_iequal(next, "host")) {
                char *ipstr = strtok_r(NULL, " \t", &saveptr);
                if (!ipstr) break;
                struct in_addr a;
                if (inet_pton(AF_INET, ipstr, &a) == 1) { out->has_src_ip = 1; out->src_ip = a.s_addr; }
                continue;
            } else if (str_iequal(next, "port")) {
                char *ps = strtok_r(NULL, " \t", &saveptr);
                if (!ps) break;
                int p = atoi(ps);
                if (p > 0 && p <= 65535) { out->has_src_port = 1; out->src_port = htons((uint16_t)p); }
                continue;
            } else {
                // push back? skip
                continue;
            }
        }
        if (str_iequal(tok, "dst")) {
            char *next = strtok_r(NULL, " \t", &saveptr);
            if (!next) break;
            if (str_iequal(next, "host")) {
                char *ipstr = strtok_r(NULL, " \t", &saveptr);
                if (!ipstr) break;
                struct in_addr a;
                if (inet_pton(AF_INET, ipstr, &a) == 1) { out->has_dst_ip = 1; out->dst_ip = a.s_addr; }
                continue;
            } else if (str_iequal(next, "port")) {
                char *ps = strtok_r(NULL, " \t", &saveptr);
                if (!ps) break;
                int p = atoi(ps);
                if (p > 0 && p <= 65535) { out->has_dst_port = 1; out->dst_port = htons((uint16_t)p); }
                continue;
            } else {
                continue;
            }
        }
    }
    free(buf);
}

int packet_matches_filter(const uint8_t* pkt, size_t size, const SimpleFilter* f) {
    if (!f) return 1;
    int any = f->match_tcp || f->match_udp || f->match_icmp || f->match_arp || f->has_src_ip || f->has_dst_ip || f->has_src_port || f->has_dst_port;
    if (!any) return 1;
    if (size < sizeof(struct EthHeader)) return 0;
    const struct EthHeader* eth = (const struct EthHeader*)pkt;
    uint16_t eth_type = ntohs(eth->ethertype);

    if (eth_type == 0x0806) { // ARP
        if (f->match_arp) return 1;
        // if host/ports specified, ARP can't match
        if (f->has_src_ip || f->has_dst_ip || f->has_src_port || f->has_dst_port) return 0;
        return 0;
    }
    if (eth_type != 0x0800) return 0;
    if (size < sizeof(struct EthHeader) + sizeof(struct IPv4Header)) return 0;
    const struct IPv4Header* ip = (const struct IPv4Header*)(pkt + sizeof(struct EthHeader));
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (size < sizeof(struct EthHeader) + ihl) return 0;
    uint8_t proto = ip->protocol;

    if ((f->match_tcp || f->match_udp || f->match_icmp) && !( (f->match_tcp && proto==IPPROTO_TCP) || (f->match_udp && proto==IPPROTO_UDP) || (f->match_icmp && proto==IPPROTO_ICMP) )) {
        return 0;
    }
    if (f->has_src_ip && ip->saddr != f->src_ip) return 0;
    if (f->has_dst_ip && ip->daddr != f->dst_ip) return 0;

    if ((f->has_src_port || f->has_dst_port)) {
        if (proto == IPPROTO_TCP) {
            size_t base = sizeof(struct EthHeader) + ihl;
            if (size < base + sizeof(struct TCPHeader)) return 0;
            const struct TCPHeader* tcp = (const struct TCPHeader*)(pkt + base);
            if (f->has_src_port && tcp->source != f->src_port) return 0;
            if (f->has_dst_port && tcp->dest != f->dst_port) return 0;
        } else if (proto == IPPROTO_UDP) {
            size_t base = sizeof(struct EthHeader) + ihl;
            if (size < base + sizeof(struct UDPHeader)) return 0;
            const struct UDPHeader* udp = (const struct UDPHeader*)(pkt + base);
            if (f->has_src_port && udp->source != f->src_port) return 0;
            if (f->has_dst_port && udp->dest != f->dst_port) return 0;
        } else {
            return 0;
        }
    }

    return 1;
}