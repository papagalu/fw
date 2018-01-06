#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include "rule.h"
#include "utils.h"

struct rule_struct rule;

bool check_rule_integrity () {
    return false;
}

bool send_to_firewall () {
    return false;
}

bool print_rule () {
    return false;
}

bool delete_rule () {
    return false;
}

bool add_rule () {
    return false;
}


int main(int argc, char **argv) {

    int c;
    int action;

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
        { "action",                required_argument, NULL,           'v' },

        { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "a:d:s:f:u:", longopts, NULL)) != -1) {
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
            case 'v':
                rule.action = optarg;
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

    if (!check_rule_integrity()) {
        printf("Bad rule!");
        exit(2);
    }

    switch (action) {
        case 0:
            print_rule();
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
