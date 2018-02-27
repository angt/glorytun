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

    if (!ret)
        printf("new mtu: %i\n", res.mtu);

    return ret;
}

static int
gt_set_timeout(int fd, unsigned long timeout)
{
    struct ctl_msg res, req = {
        .type = CTL_TIMEOUT,
        .timeout = timeout,
    };

    return ctl_reply(fd, &res, &req);
}

static int
gt_set_timetolerance(int fd, unsigned long timetolerance)
{
    struct ctl_msg res, req = {
        .type = CTL_TIMETOLERANCE,
        .timetolerance = timetolerance,
    };

    return ctl_reply(fd, &res, &req);
}

int
gt_set(int argc, char **argv)
{
    const char *dev = NULL;
    unsigned long timetolerance = 0;
    unsigned long timeout = 0;
    size_t mtu = 0;

    struct argz pathz[] = {
        {"dev", "NAME", &dev, argz_str},
        {"mtu", "BYTES", &mtu, argz_bytes},
        {"timeout", "SECONDS", &timeout, argz_time},
        {"timetolerance", "SECONDS", &timetolerance, argz_time},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    int fd = ctl_create("/run/" PACKAGE_NAME, NULL);

    if (fd == -1) {
        perror("set");
        return 1;
    }

    if (ctl_connect(fd, "/run/" PACKAGE_NAME, dev) == -1) {
        perror("set");
        ctl_delete(fd);
        return 1;
    }

    int ret = 0;

    if (mtu && gt_set_mtu(fd, mtu)) {
        perror("mtu");
        ret = 1;
    }

    if (!ret && timeout && gt_set_timeout(fd, timeout)) {
        perror("timeout");
        ret = 1;
    }

    if (!ret && timetolerance && gt_set_timetolerance(fd, timetolerance)) {
        perror("timetolerance");
        ret = 1;
    }

    ctl_delete(fd);

    return ret;
}
