#include "sniffer.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>


static void usage(const char* prog) {
    fprintf(stderr, "Usage: sudo %s -i <interface> [-f \"filter\"] [-c count]\n", prog);
    fprintf(stderr, "Example filters: \"tcp\", \"udp and src host 1.2.3.4\", \"dst port 53\"\n");
}

int main(int argc, char** argv) {
    char iface[64] = {0};
    char *filter_expr = NULL;
    unsigned int count = 0;
    int opt;
    while ((opt = getopt(argc, argv, "i:f:c:h")) != -1) {
        switch (opt) {
            case 'i': strncpy(iface, optarg, sizeof(iface)-1); break;
            case 'f': filter_expr = optarg; break;
            case 'c': count = (unsigned int)strtoul(optarg, NULL, 10); break;
            case 'h':
            default:
                usage(argv[0]);
                return 1;
        }
    }
    if (iface[0] == '\0') {
        usage(argv[0]);
        return 1;
    }
    SimpleFilter filter;
    parse_filter_expression(filter_expr, &filter);
    Sniffer s;
    if (Sniffer_init(&s, iface, &filter, count) != 0) {
        fprintf(stderr, "Failed to init sniffer\n");
        return 1;
    }
    if (Sniffer_start(&s) != 0) {
        fprintf(stderr, "Sniffer failed\n");
        Sniffer_destroy(&s);
        return 1;
    }
    Sniffer_destroy(&s);
    return 0;
}