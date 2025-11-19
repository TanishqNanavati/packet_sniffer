#include"util.h"
#include<stdio.h>
#include<arpa/inet.h>
#include<inttypes.h>
#include<string.h>



void mac_to_string(const uint8_t mac[6],char *buff,size_t bufflen){
    if(!buff || bufflen == 0) return;
    snprintf(buff,bufflen,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);  // Copies content of mac into buffer in hexadecimal format upto 2 digits
}

void ip_to_string(uint32_t ip_be,char*buff,size_t bufflen){
    if(!buff || bufflen == 0) return;
    struct in_addr a;
    a.s_addr = ip_be;
    if(inet_ntop(AF_INET,&a,buff,(socklen_t)bufflen) == NULL){  // Converts network-order IPv4 to string
        strncpy(buff,"0.0.0.0",bufflen);
        buff[bufflen-1] = '\0';
    }
}

void hex_dump(const uint8_t *data, size_t len, char *out, size_t outlen, size_t max_bytes) {
    if (!out || outlen == 0) return;

    size_t upto = (len < max_bytes) ? len : max_bytes;
    size_t pos = 0;

    for (size_t i = 0; i < upto && pos + 3 < outlen; i++) {

        int n = snprintf(out + pos, outlen - pos, "%02x", data[i]);
        if (n < 0) break;

        pos += (size_t)n;

        // newline every 16 bytes
        if ((i + 1) % 16 == 0) {
            if (pos + 2 < outlen) {
                out[pos++] = '\n';
                out[pos] = '\0';
            }
        }
        // space every 2 bytes
        else if ((i + 1) % 2 == 0) {
            if (pos + 1 < outlen) {
                out[pos++] = ' ';
                out[pos] = '\0';
            }
        }
    }

    if (len > upto)
        strncat(out, " ....", outlen - strlen(out) - 1);
}
