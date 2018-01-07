#ifndef _rule_h
#define _rule_h

typedef struct rule_struct {
    int inbound_outbound;
    char *source_ip;
    char *source_netmask;
    char *source_port;
    char *destination_ip;
    char *destination_netmask;
    char *destination_port;
    char *protocol;
    char *action;
} rule_struct;

typedef struct rule_struct_u {
    unsigned char inbound_outbound;
    unsigned int source_ip;
    unsigned int source_netmask;
    unsigned int source_port;
    unsigned int destination_ip;
    unsigned int destination_netmask;
    unsigned int destination_port;
    unsigned char protocol;
    unsigned char action;
} rule_struct_u;

#endif
