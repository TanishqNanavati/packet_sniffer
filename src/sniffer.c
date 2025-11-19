#define _GNU_SOURCE
#include "sniffer.h"
#include "parser.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "pcap_writer.h"

static volatile sig_atomic_t g_running = 1;
static void handle_sigint(int sig) { (void)sig; g_running = 0; }

int Sniffer_init(Sniffer* s, const char* interface, const SimpleFilter* filter, unsigned int count) {
    if (!s || !interface) return -1;

    strncpy(s->iface, interface, sizeof(s->iface)-1);
    s->iface[sizeof(s->iface)-1] = '\0';

    s->sockfd = -1;

    if (filter) {
        s->filter = *filter;
    } else {
        memset(&s->filter, 0, sizeof(s->filter));
    }

    s->count = count;

    // Initialize counters
    s->total = s->tcp = s->udp = s->icmp = s->arp = 0;

    signal(SIGINT, handle_sigint);
    return 0;
}

void Sniffer_destroy(Sniffer* s) {
    if (!s) return;
    if (s->sockfd != -1) close(s->sockfd);
    s->sockfd = -1;
}

static int setup_socket(Sniffer* s) {
    s->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s->sockfd == -1) {
        fprintf(stderr, "socket(AF_PACKET) failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(s->iface);

    if (sll.sll_ifindex == 0) {
        fprintf(stderr, "Interface not found: %s\n", s->iface);
        close(s->sockfd);
        s->sockfd = -1;
        return -1;
    }

    if (bind(s->sockfd, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        fprintf(stderr, "bind failed: %s\n", strerror(errno));
        close(s->sockfd);
        s->sockfd = -1;
        return -1;
    }

    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = sll.sll_ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(s->sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        fprintf(stderr, "Warning: could not enable promiscuous mode: %s\n", strerror(errno));
    }

    return 0;
}

// Updated: accept Sniffer* so we can count packets
static void process_packet(Sniffer* s, const uint8_t* buffer, ssize_t len) {

    s->total++;  // count everything

    print_eth(buffer, (size_t)len);

    if (len < (ssize_t)sizeof(struct EthHeader)) return;
    const struct EthHeader* eth = (const struct EthHeader*)buffer;
    uint16_t etype = ntohs(eth->ethertype);

    // ================= ARP ==================
    if (etype == 0x0806) {
        s->arp++;
        print_arp(buffer, (size_t)len);
        printf("\n");
        return;
    }

    // ================= IPv4 =================
    if (etype != 0x0800) {
        printf("Non-IPv4 Ethertype: 0x%04x\n\n", etype);
        return;
    }

    if (len < (ssize_t)(sizeof(struct EthHeader) + sizeof(struct IPv4Header))) return;

    const struct IPv4Header* ip = (const struct IPv4Header*)(buffer + sizeof(struct EthHeader));
    size_t ihl = (ip->ver_ihl & 0x0F) * 4;

    print_ip(buffer, (size_t)len);

    switch (ip->protocol) {
        case IPPROTO_TCP:
            s->tcp++;
            print_tcp(buffer, (size_t)len, ihl);
            break;

        case IPPROTO_UDP:
            s->udp++;
            print_udp(buffer, (size_t)len, ihl);
            break;

        case IPPROTO_ICMP:
            s->icmp++;
            print_icmp(buffer, (size_t)len, ihl);
            break;

        default:
            printf("Other IP protocol: %u\n", ip->protocol);
            break;
    }

    printf("\n");
}

int Sniffer_start(Sniffer* s) {
    if (!s) return -1;
    if (setup_socket(s) != 0) return -1;

    fprintf(stderr, "Sniffer started on interface: %s\n", s->iface);

    const size_t BUF_SZ = 65536;
    uint8_t *buffer = malloc(BUF_SZ);
    if (!buffer) return -1;

    unsigned int seen = 0;

    while (g_running) {
        ssize_t len = recvfrom(s->sockfd, buffer, BUF_SZ, 0, NULL, NULL);
        if (len <= 0) {
            if (len == -1 && errno == EINTR) continue;
            fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
            break;
        }

        if (!packet_matches_filter(buffer, (size_t)len, &s->filter))
            continue;

        process_packet(s, buffer, len);

        ++seen;
        if (s->count > 0 && seen >= s->count)
            break;
    }

    free(buffer);

    // ================= SUMMARY =================
    fprintf(stderr, "\n=== Packet Summary (%s) ===\n", s->iface);
    fprintf(stderr, "Total packets: %lu\n", s->total);
    fprintf(stderr, "ARP packets:   %lu\n", s->arp);
    fprintf(stderr, "TCP packets:   %lu\n", s->tcp);
    fprintf(stderr, "UDP packets:   %lu\n", s->udp);
    fprintf(stderr, "ICMP packets:  %lu\n", s->icmp);
    fprintf(stderr, "===========================\n");

    fprintf(stderr, "Sniffer stopped.\n");
    return 0;
}
