#include "pcap_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>

static FILE *g_pcap = NULL;

#pragma pack(push,1)
typedef struct pcap_hdr_s {
    uint32_t magic_number;   // magic number 
    uint16_t version_major;  // major version number 
    uint16_t version_minor;  // minor version number 
    int32_t  thiszone;       // GMT to local correct
    uint32_t sigfigs;        // accuracy of timestamps 
    uint32_t snaplen;        // max length of captured packets, in octets 
    uint32_t network;        // data link type (1 for Ethernet) 
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;        // timestamp seconds 
    uint32_t ts_usec;       // timestamp microseconds 
    uint32_t incl_len;      // number of octets of packet saved in file 
    uint32_t orig_len;      // actual length of packet 
} pcaprec_hdr_t;
#pragma pack(pop)

int pcap_writer_open(const char *filename) {
    if (!filename) return -1;
    if (g_pcap) {
        // already open
        return 0;
    }
    g_pcap = fopen(filename, "wb");
    if (!g_pcap) return -1;

    pcap_hdr_t gh;
    gh.magic_number = 0xa1b2c3d4u; // standard pcap magic (microsecond)
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 1; // DLT_EN10MB (Ethernet)

    if (fwrite(&gh, sizeof(gh), 1, g_pcap) != 1) {
        fclose(g_pcap);
        g_pcap = NULL;
        return -1;
    }
    fflush(g_pcap);
    return 0;
}

int pcap_writer_write_packet(const uint8_t *data, size_t len) {
    if (!g_pcap || !data || len == 0) return -1;

    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return -1;

    pcaprec_hdr_t rh;
    rh.ts_sec = (uint32_t)tv.tv_sec;
    rh.ts_usec = (uint32_t)tv.tv_usec;
    rh.incl_len = (uint32_t)len;
    rh.orig_len = (uint32_t)len;

    if (fwrite(&rh, sizeof(rh), 1, g_pcap) != 1) return -1;
    if (fwrite(data, 1, len, g_pcap) != len) return -1;
    fflush(g_pcap);
    return 0;
}

void pcap_writer_close(void) {
    if (!g_pcap) return;
    fclose(g_pcap);
    g_pcap = NULL;
}
