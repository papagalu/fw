#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include "rule.h"
#include "utils.h"

struct rule_struct rule;
struct rule_struct_u rule_u;
char *rule_number;
int num;

FILE * open_fd (char *path, char *permissions) {
    FILE *fd = fopen(path, permissions);
    if( NULL == fd ) {
        printf("Cannot open %s\n", path);
        return NULL;
    }
    return fd;
}

void close_fd (FILE *fd) {
    fclose(fd);
}

bool send_to_firewall (char *str) {

    FILE *fd = open_fd("/proc/firewall", "w");
    if (NULL == fd) { return false; }

    fprintf(fd, "%s", str);
    close_fd(fd);

    return true;
}

bool delete_rule (void) {
    char *buff;
    int len = 0;
    buff = malloc(sizeof(char) * 10);

    len = sprintf(buff, "d %s\n", rule_number);
    if (0 == len) {return false;}
    send_to_firewall(buff);

    free(buff);
    return true;
}

void convert_rule_to_u (void) {
    rule_u.inbound_outbound = rule.inbound_outbound;
    rule_u.source_ip = ip_str_to_int(rule.source_ip);
    rule_u.source_netmask = ip_str_to_int(rule.source_netmask);
    rule_u.source_port = port_str_to_int(rule.source_port);
    rule_u.destination_ip = ip_str_to_int(rule.destination_ip);
    rule_u.destination_netmask = ip_str_to_int(rule.destination_netmask);
    rule_u.destination_port = port_str_to_int(rule.destination_port);
    rule_u.protocol = get_protocol_to_int(rule.protocol);
    rule_u.action = get_action_to_int(rule.action);
}

void convert_rule_from_u (void) {
    rule.inbound_outbound = rule_u.inbound_outbound;
    rule.source_ip = ip_int_to_str(rule_u.source_ip);
    rule.source_netmask = ip_int_to_str(rule_u.source_netmask);
    rule.source_port = port_int_to_str(rule_u.source_port);
    rule.destination_ip = ip_int_to_str(rule_u.destination_ip);
    rule.destination_netmask = ip_int_to_str(rule_u.destination_netmask);
    rule.destination_port = port_int_to_str(rule_u.destination_port);
    rule.protocol = get_protocol_to_str(rule_u.protocol);
    rule.action = get_action_to_str(rule_u.action);
}

bool add_rule (void) {

    char *buff;
    int len = 0;
    buff = malloc(sizeof(char) * 2048);

    convert_rule_to_u();
    sprintf(buff, "a %d %d %d %d %d %d %d %d %d\n",
            rule_u.inbound_outbound,
            rule_u.source_ip,
            rule_u.source_netmask,
            rule_u.source_port,
            rule_u.destination_ip,
            rule_u.destination_netmask,
            rule_u.destination_port,
            rule_u.protocol,
            rule_u.action);

    send_to_firewall(buff);

    free(buff);
    return false;
}

void print_rule () {
    printf("%d  ", num);
    printf("%d  ", rule.inbound_outbound);
    printf("%s  ", rule.source_ip);
    printf("%s  ", rule.source_netmask);
    printf("%s  ", rule.source_port);
    printf("%s  ", rule.destination_ip);
    printf("%s  ", rule.destination_netmask);
    printf("%s  ", rule.destination_port);
    printf("%s  ", rule.protocol);
    printf("%s\n", rule.action);
}

void print_firewall_rules () {
    char *line = NULL;
    ssize_t len;
    ssize_t read;

    FILE *fd = open_fd("/proc/firewall", "r");

    while ((read = getline(&line, &len, fd)) != -1) {
        sscanf(line, "%d %hhu %d %d %d %d %d %d %hhu %hhu\n", &num,
            &rule_u.inbound_outbound,
            &rule_u.source_ip,
            &rule_u.source_netmask,
            &rule_u.source_port,
            &rule_u.destination_ip,
            &rule_u.destination_netmask,
            &rule_u.destination_port,
            &rule_u.protocol,
            &rule_u.action);

        convert_rule_from_u();
        print_rule();
    }

    close_fd(fd);
    if (line) free(line);
}


int main(int argc, char **argv) {

    int c;
    int action = -1;

    rule.inbound_outbound = -1;
    rule.source_ip = NULL;
    rule.source_netmask = NULL;
    rule.source_port = NULL;
    rule.destination_ip = NULL;
    rule.destination_netmask = NULL;
    rule.destination_port = NULL;
    rule.action = NULL;

    struct option longopts[] = {
        { "in",                    no_argument, &rule.inbound_outbound, 0 },
        { "out",                   no_argument, &rule.inbound_outbound, 1 },

        { "print",                 no_argument,       NULL,           'p' },
        { "delete",                no_argument,       NULL,           'd' },
        { "add",                   no_argument,       NULL,           'a' },

        { "source-ip",             required_argument, NULL,           'q' },
        { "source-netmask",        required_argument, NULL,           'w' },
        { "source-port",           required_argument, NULL,           'e' },
        { "destination-ip",        required_argument, NULL,           'z' },
        { "destination-netmask",   required_argument, NULL,           'x' },
        { "destination-port",      required_argument, NULL,           'c' },
        { "protocol",              required_argument, NULL,           'b' },
        { "action",                required_argument, NULL,           'v' },
        { "rule_number",           required_argument, NULL,           'n' },

        { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "pda:q:w:e:z:x:c:v:n:", longopts, NULL)) != -1) {
        switch (c) {
            case 'p': // print the rules of our firewall
                action = 0;
                break;
            case 'd': // delete a rule of our firewall
                action = 1;
                break;
            case 'a': // add a rule to our firewall
                action = 2;
                break;
            case 'q':
                rule.source_ip = optarg;
                break;
            case 'w':
                rule.source_netmask = optarg;
                break;
            case 'e':
                rule.source_port = optarg;
                break;
            case 'z':
                rule.destination_ip = optarg;
                break;
            case 'x':
                rule.destination_netmask = optarg;
                break;
            case 'c':
                rule.destination_port = optarg;
                break;
            case 'b':
                rule.protocol = optarg;
                break;
            case 'v':
                rule.action = optarg;
                break;
            case 'n':
                rule_number = optarg;
                break;
            case 0:     /* getopt_long() set a variable, just keep going */
                break;
            case ':':   /* missing option argument */
                fprintf(stderr, "%s: option `-%c' requires an argument\n",
                        argv[0], optopt);
                break;
            case '?':
            default:    /* invalid option */
                fprintf(stderr, "%s: option `-%c' is invalid: ignored\n",
                        argv[0], optopt);
                break;
        }
    }

    switch (action) {
        case 0:
            print_firewall_rules();
            break;
        case 1:
            delete_rule();
            break;
        case 2:
            add_rule();
            break;
        default:
            break;
    }
}
