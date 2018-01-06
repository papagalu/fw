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
}rule_struct;

#endif
