#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>
#include <dirent.h>
#include <sys/un.h>

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

    if (str_empty(reply.status.addr)) {
        printf("server %s:\n"
               "  mtu:       %zu\n"
               "  auto mtu:  %s\n"
               "  bind port: %hu\n"
               "  cipher:    %s\n"
               "  ipv4:      %s\n"
               "  ipv6:      %s\n",
               dev,
               reply.status.mtu,
               reply.status.mtu_auto ? "enabled" : "disabled",
               reply.status.bind_port,
               reply.status.chacha ? "chacha20poly1305" : "aes256gcm",
               reply.status.ipv4 ? "enabled" : "disabled",
               reply.status.ipv6 ? "enabled" : "disabled");
    } else {
        printf("client %s:\n"
               "  host:      %s\n"
               "  port:      %hu\n"
               "  mtu:       %zu\n"
               "  auto mtu:  %s\n"
               "  bind port: %hu\n"
               "  cipher:    %s\n"
               "  ipv4:      %s\n"
               "  ipv6:      %s\n",
               dev,
               reply.status.addr, reply.status.port,
               reply.status.mtu,
               reply.status.mtu_auto ? "enabled" : "disabled",
               reply.status.bind_port,
               reply.status.chacha ? "chacha20poly1305" : "aes256gcm",
               reply.status.ipv4 ? "enabled" : "disabled",
               reply.status.ipv6 ? "enabled" : "disabled");
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
