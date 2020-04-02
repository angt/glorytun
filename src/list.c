#include "common.h"
#include "ctl.h"

#include "../argz/argz.h"

#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/un.h>

int
gt_list(int argc, char **argv)
{
    struct argz showz[] = {
        {"list", NULL, NULL, argz_option},
        {NULL}};

    if (argz(showz, argc, argv))
        return 1;

    char dir[64];

    if (!ctl_rundir(dir, sizeof(dir)))
        return 0;

    DIR *dp = opendir(dir);

    if (!dp)
        return 0;

    struct dirent *d = NULL;

    while (d = readdir(dp), d) {
        if (d->d_name[0] == '.')
            continue;

        int fd = ctl_connect(d->d_name);

        if (fd < 0)
            continue;

        printf("%s\n", d->d_name);
        close(fd);
    }

    closedir(dp);

    return 0;
}
