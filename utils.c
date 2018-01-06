#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

unsigned int port_str_to_int(char *port_str) {

    unsigned int port = 0;
    int i = 0;

    if (port_str == NULL) {
        return 0;
    }

    while (port_str[i]!='\0') {
        port = port*10 + (port_str[i]-'0');
        ++i;
    }

    return port;
}

char *port_int_to_str(unsigned int port) {
    int digits = 1;
    if (port < 0) return NULL;
    while (port > 9) {
        port /= 10;
        digits++;
    }

    char *t_str = malloc(sizeof(char) * digits);
    sprintf(t_str, "%d", port);

    return t_str;
}

unsigned int ip_str_to_int(char *ip) {
    unsigned v = 0;
    int i;
    const char * start;

    start = ip;
    for (i = 0; i < 4; i++) {
        char c;
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return -1;
            }
        }
        if (n >= 256) {
            return -1;
        }
        v *= 256;
        v += n;
    }
    return v;
}


char *ip_int_to_str(unsigned int ip) {
    unsigned char bytes[4];

    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    char *ip_str = malloc(sizeof(char) * 15);

    sprintf(ip_str, "%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);

    return ip_str;
}

bool check_ip_integrity(unsigned int ip1, unsigned int ip2, unsigned int mask) {

    if ((ip1 & mask) == (ip2 & mask)) {
        return true;
    } else {
        return false;
    }
}
