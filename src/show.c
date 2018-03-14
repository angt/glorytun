#include "common.h"
#include "ctl.h"
#include "str.h"

#include "../argz/argz.h"

#include <stdio.h>
#include <sys/socket.h>
#include <dirent.h>
#include <sys/un.h>
#include <arpa/inet.h>

static int
gt_show_dev_status(int fd, const char *dev)
{
    struct ctl_msg res, req = {.type = CTL_STATUS};

    if (ctl_reply(fd, &res, &req))
        return -1;

    char bindstr[INET6_ADDRSTRLEN] = {0};
    char peerstr[INET6_ADDRSTRLEN] = {0};

    if (gt_toaddr(bindstr, sizeof(bindstr),
                  (struct sockaddr *)&res.status.bind))
        return -2;

    int server = gt_toaddr(peerstr, sizeof(peerstr),
                           (struct sockaddr *)&res.status.peer);

    if (server) {
        printf("server %s:\n"
               "  bind:      %s port %"PRIu16"\n"
               "  mtu:       %zu\n"
               "  cipher:    %s\n",
               dev,
               bindstr, gt_get_port((struct sockaddr *)&res.status.bind),
               res.status.mtu,
               res.status.chacha ? "chacha20poly1305" : "aes256gcm");
    } else {
        printf("client %s:\n"
               "  bind:      %s port %"PRIu16"\n"
               "  peer:      %s port %"PRIu16"\n"
               "  mtu:       %zu\n"
               "  cipher:    %s\n",
               dev,
               bindstr, gt_get_port((struct sockaddr *)&res.status.bind),
               peerstr, gt_get_port((struct sockaddr *)&res.status.peer),
               res.status.mtu,
               res.status.chacha ? "chacha20poly1305" : "aes256gcm");
    }

    return 0;
}

static int
gt_show_dev(const char *dev)
{
    int fd = ctl_connect(GT_RUNDIR, dev);

    if (fd == -1) {
        perror(dev);
        return -1;
    }

    int ret = gt_show_dev_status(fd, dev);

    if (ret == -1)
        perror(dev);

    if (ret == -2)
        gt_log("%s: bad reply from server\n", dev);

    ctl_delete(fd);

    return ret;
}

int
gt_show(int argc, char **argv)
{
    const char *dev = NULL;

    struct argz showz[] = {
        {"dev", "NAME", &dev, argz_str},
        {NULL}};

    if (argz(showz, argc, argv))
        return 1;

    if (dev) {
        gt_show_dev(dev);
        return 0;
    }

    DIR *dp = opendir(GT_RUNDIR);

    if (!dp) {
        if (errno == ENOENT)
            return 0;
        perror("show");
        return 1;
    }

    struct dirent *d = NULL;

    while (d = readdir(dp), d) {
        if (d->d_name[0] != '.')
            gt_show_dev(d->d_name);
    }

    closedir(dp);

    return 0;
}
