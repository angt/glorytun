#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>

#include "../argz/argz.h"

static int
gt_set_mtu(int fd, size_t mtu)
{
    struct ctl_msg res, req = {
        .type = CTL_MTU,
        .mtu = mtu,
    };

    int ret = ctl_reply(fd, &res, &req);

    if (ret) {
        perror("set mtu");
        return 1;
    }

    printf("mtu set to %i\n", res.mtu);

    return 0;
}

static int
gt_set_timeout(int fd, unsigned long timeout)
{
    struct ctl_msg res, req = {
        .type = CTL_TIMEOUT,
        .timeout = timeout,
    };

    int ret = ctl_reply(fd, &res, &req);

    if (ret) {
        perror("set timeout");
        return 1;
    }

    return 0;
}

static int
gt_set_timetolerance(int fd, unsigned long timetolerance)
{
    struct ctl_msg res, req = {
        .type = CTL_TIMETOLERANCE,
        .timetolerance = timetolerance,
    };

    int ret = ctl_reply(fd, &res, &req);

    if (ret) {
        perror("set timetolerance");
        return 1;
    }

    return 0;
}

static int
gt_set_tc(int fd, int tc)
{
    struct ctl_msg res, req = {
        .type = CTL_TC,
        .tc = tc,
    };

    int ret = ctl_reply(fd, &res, &req);

    if (ret) {
        perror("set tc");
        return 1;
    }

    return 0;
}

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
    size_t mtu;
    int tc;
    unsigned long timetolerance;
    unsigned long timeout;

    struct argz pathz[] = {
        {"dev", "NAME", &dev, argz_str},
        {"mtu", "BYTES", &mtu, argz_bytes},
        {"tc", "CS|AF|EF", &tc, gt_argz_tc},
        {"timeout", "SECONDS", &timeout, argz_time},
        {"timetolerance", "SECONDS", &timetolerance, argz_time},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    int fd = ctl_connect("/run/" PACKAGE_NAME, dev);

    if (fd == -1) {
        perror("set");
        return 1;
    }

    int ret = 0;

    if (argz_is_set(pathz, "mtu"))
        ret |= gt_set_mtu(fd, mtu);

    if (argz_is_set(pathz, "tc"))
        ret |= gt_set_tc(fd, tc);

    if (argz_is_set(pathz, "timeout"))
        ret |= gt_set_timeout(fd, timeout);

    if (argz_is_set(pathz, "timetolerance"))
        ret |= gt_set_timetolerance(fd, timetolerance);

    ctl_delete(fd);

    return ret;
}
