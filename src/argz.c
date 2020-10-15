#include "common.h"
#include "ctl.h"
#include "argz.h"

#include <stdio.h>

#include "../argz/argz.h"

void
gt_argz_print(const char *str)
{
    printf("%s\n", str);
}

int
gt_argz_dev(int argc, char **argv, void *data)
{
    if (argz_help_me(argc, argv)) {
        ctl_foreach(gt_argz_print);
    } else if (argc > 1) {
        memcpy(data, &argv[1], sizeof(char *));
        return argc - 2;
    } else {
        gt_log("Option %s requires a tunnel device\n", argv[0]);
    }
    return -1;
}

int
gt_argz_tc(int argc, char **argv, void *data)
{
    if (argz_help_me(argc, argv)) {
        for (unsigned i=0; i <= 7; i++)
            printf("CS%u\n", i);
        for (unsigned i=1; i <= 4; i++)
            for (unsigned j=1; j <= 3; j++)
                printf("AF%u%u\n", i, j);
        printf("EF\n");
    } else if (argc > 1) {
        int val = 0;
        const char *s = argv[1];

        if ((s[0] == 'C') && (s[1] == 'S') &&
            (s[2] >= '0') && (s[2] <= '7') && !s[3]) {
            val = (s[2] - '0') << 3;
        } else if ((s[0] == 'A') && (s[1] == 'F') &&
                   (s[2] >= '1') && (s[2] <= '4') &&
                   (s[3] >= '1') && (s[3] <= '3') && !s[4]) {
            val = ((s[2] - '0') << 3) | ((s[3] - '0') << 1);
        } else if ((s[0] == 'E') && (s[1] == 'F') && !s[2]) {
            val = 46;
        } else {
            gt_log("Option %s is not a valid tc value\n", argv[1]);
            return -1;
        }
        memcpy(data, &val, sizeof(int));
        return argc - 2;
    } else {
        gt_log("Option %s requires a value\n", argv[0]);
    }
    return -1;
}

int
gt_argz_addr_ip(int argc, char **argv, void *data)
{
    struct gt_argz_addr *addr = (struct gt_argz_addr *)data;

    if (argz_help_me(argc, argv)) {
        char tmp[INET6_ADDRSTRLEN];
        if (!gt_toaddr(tmp, sizeof(tmp), &addr->sa))
            printf("%s\n", tmp);
    } else if (argc > 1) {
        if (inet_pton(AF_INET, argv[1], &addr->sin.sin_addr) == 1) {
            addr->ss.ss_family = AF_INET;
        } else if (inet_pton(AF_INET6, argv[1], &addr->sin6.sin6_addr) == 1) {
            addr->ss.ss_family = AF_INET6;
        } else {
            gt_log("Option %s is not a valid IP address\n", argv[1]);
            return -1;
        }
        return argc - 2;
    } else {
        gt_log("Option %s requires an IP address\n", argv[0]);
    }
    return -1;
}

int
gt_argz_addr(int argc, char **argv, void *data)
{
    struct gt_argz_addr *addr = (struct gt_argz_addr *)data;

    struct argz_ull port = {
        .value = addr->port,
        .min = 0,
        .max = 0xFFFF,
    };
    struct argz z[] = {
        {"addr", "IP address", gt_argz_addr_ip,  data},
        {"port", "Port number",       argz_ull, &port},
        {0}};

    int ret = argz(argc, argv, z);
    gt_set_port(&addr->sa, port.value);
    return ret;
}
