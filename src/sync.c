#include "common.h"
#include "ctl.h"
#include "str.h"

#include "../argz/argz.h"

#include <stdio.h>
#include <dirent.h>

static int
gt_sync_dev(const char *dev)
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

    const int ret = ctl_reply(fd, &res, &req);

    if (ret == -1)
        perror("sync");

    ctl_delete(fd);

    return ret;
}

int
gt_sync(int argc, char **argv)
{
    const char *dev = NULL;

    struct argz syncz[] = {
        {"dev", "NAME", &dev, argz_str},
        {NULL}};

    if (argz(syncz, argc, argv))
        return 1;

    if (dev) {
        gt_sync_dev(dev);
        return 0;
    }

    DIR *dp = opendir(GT_RUNDIR);

    if (!dp) {
        if (errno == ENOENT)
            return 0;
        perror("sync");
        return 1;
    }

    struct dirent *d = NULL;

    while (d = readdir(dp), d) {
        if (d->d_name[0] != '.')
            gt_sync_dev(d->d_name);
    }

    closedir(dp);

    return 0;
}
