#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>

#include "../argz/argz.h"

static ssize_t
gt_reply(int fd, struct ctl_msg *res, struct ctl_msg *req)
{
    if ((send(fd, req, sizeof(struct ctl_msg), 0) == -1) ||
        (recv(fd, res, sizeof(struct ctl_msg), 0) == -1)) {
        int err = errno;
        ctl_delete(fd);
        errno = err;
        return -1;
    }

    if (res->type == CTL_REPLY) {
        if (res->reply < 0) {
            errno = res->reply;
            return -1;
        }
    } else {
        errno = EINTR;
        return -1;
    }

    return 0;
}

static int
gt_set_mtu(int fd, size_t mtu)
{
    struct ctl_msg res, req = {
        .type = CTL_MTU,
        .mtu = mtu,
    };

    int ret = gt_reply(fd, &res, &req);

    if (!ret)
        printf("new mtu: %i\n", res.reply);

    return ret;
}

static int
gt_set_timeout(int fd, unsigned long timeout)
{
    struct ctl_msg res, req = {
        .type = CTL_TIMEOUT,
        .timeout = timeout,
    };

    return gt_reply(fd, &res, &req);
}

static int
gt_set_timetolerance(int fd, unsigned long timetolerance)
{
    struct ctl_msg res, req = {
        .type = CTL_TIMETOLERANCE,
        .timetolerance = timetolerance,
    };

    return gt_reply(fd, &res, &req);
}

int
gt_set(int argc, char **argv)
{
    const char *dev = "tun0";
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
        perror("ctl_create");
        return 1;
    }

    if (ctl_connect(fd, "/run/" PACKAGE_NAME, dev) == -1) {
        gt_log("couldn't connect to %s\n", dev);
        ctl_delete(fd);
        return 1;
    }

    if (mtu && gt_set_mtu(fd, mtu)) {
        perror("mtu");
        return 1;
    }

    if (timeout && gt_set_timeout(fd, timeout)) {
        perror("timeout");
        return 1;
    }

    if (timetolerance && gt_set_timetolerance(fd, timetolerance)) {
        perror("timetolerance");
        return 1;
    }

    ctl_delete(fd);

    return 0;
}
