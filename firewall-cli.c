#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

static struct rule_struct {
    char *source_ip;
    char *source_netmask;
    char *source_port;
    char *destination_ip;
    char *destination_netmask;
    char *destination_port;
} rule;

int send_to_firewall () {

}


int main(int argc, char **argv) {
    int c;

    struct option longopts[] = {
       { "all",     no_argument,       NULL,         'a' },
       { "file",    required_argument, NULL,         'f' },
       { "help",    no_argument,       NULL,         's' },
       { "verbose", no_argument,       NULL,         'd' },
       { "user"   , optional_argument, NULL,         'u' },
       { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "a:d:s:f:u:", longopts, NULL)) != -1) {
        switch (c) {
            case 'a':
                printf("case a\n");
                break;
            case 'f':
                printf("case f\n");
                break;
            case 's':
                printf("case s\n");
                break;
            case 'd':
                printf("case d\n");
                break;
            case 'u':
                printf("case u\n");
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

}
