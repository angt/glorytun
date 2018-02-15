#include "common.h"
#include "ctl.h"
#include "str.h"

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
gt_show_tunnel(int fd, const char *dev)
{
    if (ctl_connect(fd, "/run/" PACKAGE_NAME, dev) == -1) {
        perror(dev);
        return -1;
    }

    struct ctl_msg reply, msg = {
        .type = CTL_STATUS,
    };

    if ((send(fd, &msg, sizeof(msg), 0) == -1) ||
        (recv(fd, &reply, sizeof(reply), 0) == -1)) {
        perror(dev);
        return -1;
    }

    if (reply.type != CTL_STATUS_REPLY)
        return -1;

    char bindstr[INET6_ADDRSTRLEN] = {0};
    char peerstr[INET6_ADDRSTRLEN] = {0};

    if (gt_ss_addr(bindstr, sizeof(bindstr), &reply.status.bind) ||
        gt_ss_addr(peerstr, sizeof(peerstr), &reply.status.peer))
        return -1;

    if (reply.status.peer.ss_family == 0) {
        printf("server %s:\n"
               "  bind:      %s port %hu\n"
               "  mtu:       %zu\n"
               "  auto mtu:  %s\n"
               "  cipher:    %s\n",
               dev,
               bindstr, gt_ss_port(&reply.status.bind),
               reply.status.mtu,
               reply.status.mtu_auto ? "enabled" : "disabled",
               reply.status.chacha ? "chacha20poly1305" : "aes256gcm");
    } else {
        printf("client %s:\n"
               "  bind:      %s port %hu\n"
               "  peer:      %s port %hu\n"
               "  mtu:       %zu\n"
               "  auto mtu:  %s\n"
               "  cipher:    %s\n",
               dev,
               bindstr, gt_ss_port(&reply.status.bind),
               peerstr, gt_ss_port(&reply.status.peer),
               reply.status.mtu,
               reply.status.mtu_auto ? "enabled" : "disabled",
               reply.status.chacha ? "chacha20poly1305" : "aes256gcm");
    }

    return 0;
}

int
gt_show(int argc, char **argv)
{
    DIR *dp = opendir("/run/" PACKAGE_NAME);

    if (!dp) {
        if (errno == ENOENT)
            return 0;
        perror("show");
        return 1;
    }

    struct dirent *d = NULL;

    while (d = readdir(dp), d) {
        if (d->d_name[0] == '.')
            continue;

        int fd = ctl_create("/run/" PACKAGE_NAME, NULL);

        if (fd == -1) {
            perror("ctl_create");
            return 1;
        }

        gt_show_tunnel(fd, d->d_name);
        ctl_delete(fd);
    }

    closedir(dp);

    return 0;
}
