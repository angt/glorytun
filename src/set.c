#include "common.h"
#include "ctl.h"

#include <stdio.h>

#include "../argz/argz.h"

static int
gt_argz_tc(void *data, int argc, char **argv)
{
    if (argc < 1 || !argv[0])
        return -1;

    int val = 0;
    const char *s = argv[0];

    if ((s[0] == 'C') && (s[1] == 'S') &&
        (s[2] >= '0') && (s[2] <= '7') && !s[3]) {
        val = (s[2] - '0') << 3;
    } else if ((s[0] == 'A') && (s[1] == 'F') &&
               (s[2] >= '1') && (s[2] <= '4') &&
               (s[3] >= '1') && (s[3] <= '3') && !s[4]) {
        val = ((s[2] - '0') << 3) | ((s[3] - '0') << 1);
    } else if ((s[0] == 'E') && (s[1] == 'F') && !s[2]) {
        val = 46;
    } else return -1;

    if (data)
        *(int *)data = val;

    return 1;
}

int
gt_set(int argc, char **argv)
{
    const char *dev = NULL;
    unsigned long kxtimeout = 0;
    unsigned long timetolerance = 0;
    unsigned long keepalive = 0;
    int tc = 0;

    struct argz pathz[] = {
        {"dev", "NAME", &dev, argz_str},
        {"tc", "CS|AF|EF", &tc, gt_argz_tc},
        {"kxtimeout", "SECONDS", &kxtimeout, argz_time},
        {"timetolerance", "SECONDS", &timetolerance, argz_time},
        {"keepalive", "SECONDS", &keepalive, argz_time},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    struct ctl_msg req = {
        .type = CTL_CONF,
        .conf = {
            .tc = tc ? (tc << 1) | 1 : 0,
            .kxtimeout = kxtimeout * UINT64_C(1000),
            .timetolerance = timetolerance * UINT64_C(1000),
            .keepalive = keepalive * UINT64_C(1000),
        },
    }, res = {0};

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return 1;
    }

    int ret = ctl_reply(fd, &res, &req);

    char t0[32], t1[32], t2[32];
    gt_totime(t0, sizeof(t0), res.conf.kxtimeout / 1000);
    gt_totime(t1, sizeof(t1), res.conf.timetolerance / 1000);
    gt_totime(t2, sizeof(t2), res.conf.keepalive / 1000);

    printf("set kxtimeout %s timetolerance %s keepalive %s tc %i\n", t0, t1, t2, res.conf.tc);

    if (ret)
        perror("set");

    ctl_delete(fd);

    return !!ret;
}
