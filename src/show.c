#include "common.h"
#include "ctl.h"
#include "str.h"

#include "../argz/argz.h"

#include <stdio.h>
#include <sys/socket.h>
#include <dirent.h>
#include <sys/un.h>
#include <arpa/inet.h>

static unsigned short
gt_ss_port(struct sockaddr_storage *ss)
{
    switch (ss->ss_family) {
    case AF_INET:
        return ntohs(((struct sockaddr_in *)ss)->sin_port);
    case AF_INET6:
        return ntohs(((struct sockaddr_in6 *)ss)->sin6_port);
    }

    return 0;
}

static int
gt_ss_addr(char *str, size_t size, struct sockaddr_storage *ss)
{
    switch (ss->ss_family) {
    case AF_INET:
        return -!inet_ntop(AF_INET,
                           &((struct sockaddr_in *)ss)->sin_addr, str, size);
    case AF_INET6:
        return -!inet_ntop(AF_INET6,
                           &((struct sockaddr_in6 *)ss)->sin6_addr, str, size);
    }

    return -1;
}

static int
gt_show_dev_status(int fd, const char *dev)
{
    if (ctl_connect(fd, "/run/" PACKAGE_NAME, dev) == -1)
        return -1;

    struct ctl_msg res, req = {.type = CTL_STATUS};

    if (ctl_reply(fd, &res, &req))
        return -1;

    char bindstr[INET6_ADDRSTRLEN] = {0};
    char peerstr[INET6_ADDRSTRLEN] = {0};

    if (gt_ss_addr(bindstr, sizeof(bindstr), &res.status.bind))
        return -2;

    int server = gt_ss_addr(peerstr, sizeof(peerstr), &res.status.peer);

    if (server) {
        printf("server %s:\n"
               "  bind:      %s port %hu\n"
               "  mtu:       %zu\n"
               "  auto mtu:  %s\n"
               "  cipher:    %s\n",
               dev,
               bindstr, gt_ss_port(&res.status.bind),
               res.status.mtu,
               res.status.mtu_auto ? "enabled" : "disabled",
               res.status.chacha ? "chacha20poly1305" : "aes256gcm");
    } else {
        printf("client %s:\n"
               "  bind:      %s port %hu\n"
               "  peer:      %s port %hu\n"
               "  mtu:       %zu\n"
               "  auto mtu:  %s\n"
               "  cipher:    %s\n",
               dev,
               bindstr, gt_ss_port(&res.status.bind),
               peerstr, gt_ss_port(&res.status.peer),
               res.status.mtu,
               res.status.mtu_auto ? "enabled" : "disabled",
               res.status.chacha ? "chacha20poly1305" : "aes256gcm");
    }

    return 0;
}

static int
gt_show_dev(const char *dev)
{
    int fd = ctl_create("/run/" PACKAGE_NAME, NULL);

    if (fd < 0) {
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

    DIR *dp = opendir("/run/" PACKAGE_NAME);

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
