#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>
#include "parser.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char iface[64];        // stores network interface name
    int sockfd;            // file descriptor storing raw socket file
    SimpleFilter filter;
    unsigned int count;
} Sniffer;

int Sniffer_init(Sniffer* s, const char* interface, const SimpleFilter* filter, unsigned int count);
void Sniffer_destroy(Sniffer* s);
int Sniffer_start(Sniffer* s);

#ifdef __cplusplus
}
#endif

#endif 