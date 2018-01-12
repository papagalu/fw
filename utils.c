#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

unsigned int port_str_to_int (char *port_str) {

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

char *port_int_to_str (unsigned int port) {
    int digits = 1;
    int temp=port;
    if (port < 0) return NULL;
    while (port > 9) {
        port /= 10;
        digits++;
    }
    char *t_str = malloc(sizeof(char) * digits);
    sprintf(t_str, "%d", temp);
    return t_str;
    }

unsigned int ip_str_to_int (char *ip) {
    unsigned v = 0;
    int i;
    const char * start;

    if(NULL == ip) {
        return 0;
    }

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


char *ip_int_to_str (unsigned int ip) {
    unsigned char bytes[4];

    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    char *ip_str = malloc(sizeof(char) * 15);

    sprintf(ip_str, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

    return ip_str;
}

bool check_ip_integrity (unsigned int ip1, unsigned int ip2, unsigned int mask) {

    if ((ip1 & mask) == (ip2 & mask)) {
        return true;
    } else {
        return false;
    }
}

char * get_protocol_to_str (int option) {
    char *buff = malloc(sizeof(char) * 4);
    switch(option) {
        case 0:
            sprintf(buff, "ALL");
            break;
        case 1:
            sprintf(buff, "TCP");
            break;
        case 2:
            sprintf(buff, "TCP");
            break;
        default:
            buff = "NONE";
    }
    return buff;
}

unsigned int get_protocol_to_int (char *str) {
     if (NULL == str) {
        return 0;
    }
    int ret = -1;
    switch (str[0]) {
        case 'A':
            ret = 0;
            break;
        case 'T':
            ret = 1;
            break;
        case 'U':
            ret = 2;
            break;
        default:
            ret = 0;
            break;
    }
    return ret;
}

char * get_action_to_str (int option) {
    char *buff = malloc(sizeof(char) * 10);
    switch(option) {
        case 0:
            sprintf(buff, "BLOCK");
            break;
        case 1:
            sprintf(buff, "UNBLOCK");
            break;
        default:
            buff = "NONE";
    }
    return buff;
}

unsigned int get_action_to_int (char *str) {
    if (NULL == str) {
        return -1;
    }
    int ret = -1;
    switch (str[0]) {
        case 'B':
            ret = 0;
            break;
        case 'U':
            ret = 1;
            break;
        default:
            ret = -1;
            break;
    }
    return ret;
}

