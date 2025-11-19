#ifndef PCAP_WRITER_H
#define PCAP_WRITER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


int pcap_writer_open(const char *filename);

int pcap_writer_write_packet(const uint8_t *data, size_t len);

void pcap_writer_close(void);

#ifdef __cplusplus
}
#endif

#endif // PCAP_WRITER_H
