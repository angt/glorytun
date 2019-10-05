#include "common.h"
#include "ctl.h"
#include "str.h"

#include "../argz/argz.h"

#include <stdio.h>
#include <sys/socket.h>
#include <dirent.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>

static int
gt_show_status(int fd)
{
    struct ctl_msg res, req = {.type = CTL_STATUS};

    if (ctl_reply(fd, &res, &req))
        return -1;

    char bindstr[INET6_ADDRSTRLEN];
    char peerstr[INET6_ADDRSTRLEN];

    gt_toaddr(bindstr, sizeof(bindstr),
              (struct sockaddr *)&res.status.bind);

    int server = gt_toaddr(peerstr, sizeof(peerstr),
                           (struct sockaddr *)&res.status.peer);

    int term = isatty(1);

    if (server) {
        printf(term ? "server %s:\n"
                      "  pid:    %li\n"
                      "  bind:   %s port %"PRIu16"\n"
                      "  mtu:    %zu\n"
                      "  cipher: %s\n"
                    : "server %s"
                      " %li"
                      " %s %"PRIu16
                      " %zu"
                      " %s"
                      "\n",
               res.status.tun_name,
               res.status.pid,
               bindstr[0] ? bindstr : "-",
               gt_get_port((struct sockaddr *)&res.status.bind),
               res.status.mtu,
               GT_CIPHER(res.status.chacha));
    } else {
        printf(term ? "client %s:\n"
                      "  pid:    %li\n"
                      "  bind:   %s port %"PRIu16"\n"
                      "  peer:   %s port %"PRIu16"\n"
                      "  mtu:    %zu\n"
                      "  cipher: %s\n"
                    : "client %s"
                      " %li"
                      " %s %"PRIu16
                      " %s %"PRIu16
                      " %zu"
                      " %s"
                      "\n",
               res.status.tun_name,
               res.status.pid,
               bindstr[0] ? bindstr : "-",
               gt_get_port((struct sockaddr *)&res.status.bind),
               peerstr[0] ? peerstr : "-",
               gt_get_port((struct sockaddr *)&res.status.peer),
               res.status.mtu,
               GT_CIPHER(res.status.chacha));
    }

    return 0;
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

    int fd = ctl_connect(GT_RUNDIR, dev);

    if (fd < 0) {
        switch (fd) {
        case -1:
            perror("show");
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

    int ret = gt_show_status(fd);

    if (ret == -1)
        perror("show");

    ctl_delete(fd);

    return !!ret;
}
