#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>

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
        *(int *)data = (val << 1) | 1;

    return 1;
}

int
gt_set(int argc, char **argv)
{
    const char *dev = NULL;

    struct ctl_msg req = {
        .type = CTL_CONF,
    }, res = {0};

    struct argz pathz[] = {
        {"dev", "NAME", &dev, argz_str},
        {"tc", "CS|AF|EF", &req.conf.tc, gt_argz_tc},
        {"kxtimeout", "SECONDS", &req.conf.kxtimeout, argz_time},
        {"timetolerance", "SECONDS", &req.conf.timetolerance, argz_time},
        {"losslimit", "PERCENT", &req.conf.losslimit, argz_percent},
        {"keepalive", "SECONDS", &req.conf.keepalive, argz_time},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        switch (fd) {
        case -1:
            perror("set");
            break;
        case CTL_ERROR_NONE:
            gt_log("no device\n");
            break;
        case CTL_ERROR_MANY:
            gt_log("please choose a device\n");
            break;
        default:
            gt_log("couldn't connect\n");
        }
        return 1;
    }

    int ret = ctl_reply(fd, &res, &req);

    if (ret)
        perror("set");

    ctl_delete(fd);

    return !!ret;
}
