#ifndef _rule_h
#define _rule_h

unsigned int port_str_to_int(char *port_str);
char *port_int_to_str(unsigned int port);

unsigned int ip_str_to_int(char *ip_str);
char *ip_int_to_str(unsigned int ip);

bool check_ip_integrity(unsigned int ip1, unsigned int ip2, unsigned int mask);

#endif
