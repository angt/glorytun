#include "common.h"
#include "ctl.h"
#include "str.h"

#include "../argz/argz.h"

#include <stdio.h>
#include <dirent.h>

static int
gt_sync_dev(const char *dev, unsigned long timeout)
{
    const int fd = ctl_connect(GT_RUNDIR, dev);

    if (fd < 0) {
        if (fd == -1)
            perror("sync");
        return 1;
    }

    struct ctl_msg res, req = {
        .type = CTL_SYNC,
    };

    int ret = ctl_reply(fd, &res, &req);

    if (!ret) {
        if (res.ms > timeout)
            ret = 1;
    } else {
        perror("sync");
    }

    ctl_delete(fd);

    return ret;
}

int
gt_sync(int argc, char **argv)
{
    const char *dev = NULL;
    unsigned long timeout = 20000;

    struct argz syncz[] = {
        {"dev", "NAME", &dev, argz_str},
        {"timeout", "SECONDS", &timeout, argz_time},
        {NULL}};

    if (argz(syncz, argc, argv))
        return 1;

    if (dev)
        return !!gt_sync_dev(dev, timeout);

    DIR *dp = opendir(GT_RUNDIR);

    if (!dp) {
        if (errno == ENOENT)
            return 0;
        perror("sync");
        return 1;
    }

    int ret = 0;
    struct dirent *d = NULL;

    while (d = readdir(dp), d) {
        if (d->d_name[0] != '.')
            ret |= !!gt_sync_dev(d->d_name, timeout);
    }

    closedir(dp);

    return ret;
}
