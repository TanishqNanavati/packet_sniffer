#ifndef UTIL_H
#define UTIL_H

#include<stdint.h>
#include<stddef.h>

#define COLOR_RESET "\x1b[0m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_WHITE "\x1b[37m"
#define COLOR_BOLD "\x1b[1m"


void mac_to_string(const uint8_t mac[6],char* buff,size_t bufflen);
void ip_to_string(const uint32_t ip_be,char* buff,size_t bufflen);
void hex_dump(const uint8_t* data,size_t len,char* out,size_t outlen,size_t max_bytes);

#endif