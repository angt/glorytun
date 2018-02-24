#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>

#include "../argz/argz.h"

int
gt_path(int argc, char **argv)
{
    const char *dev = "tun0";

    struct ctl_msg req = {
        .type = CTL_STATE,
        .path = {.state = MUD_UP},
    }, res = {0};

    struct argz pathz[] = {
        {NULL, "IPADDR", &req.path.addr, argz_addr},
        {"dev", "NAME", &dev, argz_str},
        {"up|backup|down", NULL, NULL, argz_option},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    if (argz_is_set(pathz, "backup")) {
        req.path.state = MUD_BACKUP;
    } else if (argz_is_set(pathz, "down")) {
        req.path.state = MUD_DOWN;
    }

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

    int ret = 0;

    if (ctl_reply(fd, &res, &req)) {
        perror(dev);
        ret = 1;
    }

    ctl_delete(fd);

    return ret;
}
