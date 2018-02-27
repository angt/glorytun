#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>

#include "../argz/argz.h"

int
gt_path(int argc, char **argv)
{
    const char *dev = NULL;

    struct ctl_msg req = {
        .type = CTL_STATE,
    }, res = {0};

    struct argz pathz[] = {
        {NULL, "IPADDR", &req.path.addr, argz_addr},
        {"dev", "NAME", &dev, argz_str},
        {"up|backup|down", NULL, NULL, argz_option},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    if (!req.path.addr.ss_family) {
        return 0; // TODO
    }

    if (argz_is_set(pathz, "up")) {
        req.path.state = MUD_UP;
    } else if (argz_is_set(pathz, "backup")) {
        req.path.state = MUD_BACKUP;
    } else if (argz_is_set(pathz, "down")) {
        req.path.state = MUD_DOWN;
    } else {
        return 0; // TODO
    }

    int fd = ctl_create("/run/" PACKAGE_NAME, NULL);

    if (fd == -1) {
        perror("path");
        return 1;
    }

    if ((ctl_connect(fd, "/run/" PACKAGE_NAME, dev) == -1) ||
        (ctl_reply(fd, &res, &req))) {
        perror("path");
        ctl_delete(fd);
        return 1;
    }

    ctl_delete(fd);
    return 0;
}
