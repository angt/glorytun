#pragma once

#include <netinet/in.h>

#include "../argz/argz.h"

struct gt_argz_addr {
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr_storage ss;
    };
    in_port_t port;
};

void gt_argz_print (const char *);

int gt_argz_dev  (int argc, char **argv, void *data);
int gt_argz_tc   (int argc, char **argv, void *data);
int gt_argz_addr (int argc, char **argv, void *data);
