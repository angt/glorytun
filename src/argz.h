#pragma once

#include "../mud/mud.h"
#include "../argz/argz.h"

#include <netinet/in.h>

struct gt_argz_addr {
    union mud_sockaddr sock;
};

void     gt_set_port (union mud_sockaddr *, uint16_t);
uint16_t gt_get_port (union mud_sockaddr *);

int gt_toaddr (char *, size_t, union mud_sockaddr *);
int gt_totime (char *, size_t, unsigned long long);
int gt_torate (char *, size_t, unsigned long long);

void gt_argz_print (const char *);

int gt_argz_percent_suffix (struct argz_ull *, const char *);

int gt_argz_dev     (int argc, char **argv, void *data);
int gt_argz_addr    (int argc, char **argv, void *data);
int gt_argz_addr_ip (int argc, char **argv, void *data);
