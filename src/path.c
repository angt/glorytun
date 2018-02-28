#include "common.h"
#include "ctl.h"
#include "str.h"
#include "ssutils.h"

#include <stdio.h>
#include <sys/socket.h>

#include "../argz/argz.h"

int
gt_path_status(int fd)
{
    struct ctl_msg req = {
        .type = CTL_PATH_STATUS,
    }, res = {0};

    if (send(fd, &req, sizeof(struct ctl_msg), 0) == -1)
        return -1;

    do {
        if (recv(fd, &res, sizeof(struct ctl_msg), 0) == -1)
            return -1;

        char bindstr[INET6_ADDRSTRLEN] = {0};
        char peerstr[INET6_ADDRSTRLEN] = {0};

        if (gt_ss_addr(bindstr, sizeof(bindstr), &res.path_status.local_addr) ||
            gt_ss_addr(peerstr, sizeof(peerstr), &res.path_status.addr))
            return -2;

        const char *statestr = NULL;

        switch (res.path_status.state) {
            case MUD_UP:     statestr = "UP";     break;
            case MUD_BACKUP: statestr = "BACKUP"; break;
            case MUD_DOWN:   statestr = "DOWN";   break;
            default:         return -2;
        }

        printf("path %s\n"
               "  bind:  %s\n"
               "  peer:  %s\n"
               "  rtt:   %.3f\n",
               statestr, bindstr, peerstr,
               res.path_status.rtt/(double)1e3);

    } while (res.ret == EAGAIN);

    return 0;
}

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

    int fd = ctl_connect("/run/" PACKAGE_NAME, dev);

    if (fd == -1) {
        perror("path");
        ctl_delete(fd);
        return 1;
    }

    int ret = 0;

    if (!req.path.addr.ss_family) {
        ret = gt_path_status(fd);

        if (ret == -2)
            gt_log("bad reply from server\n");
    } else {
        if (argz_is_set(pathz, "up")) {
            req.path.state = MUD_UP;
        } else if (argz_is_set(pathz, "backup")) {
            req.path.state = MUD_BACKUP;
        } else if (argz_is_set(pathz, "down")) {
            req.path.state = MUD_DOWN;
        }

        if (req.path.state)
            ret = ctl_reply(fd, &res, &req);
    }

    if (ret == -1)
        perror("path");

    ctl_delete(fd);

    return 0;
}
