#include "common.h"
#include "ctl.h"
#include "str.h"

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

        if (res.type != req.type)
            return -2;

        if (!res.ret)
            return 0;

        char bindstr[INET6_ADDRSTRLEN];
        char publstr[INET6_ADDRSTRLEN];
        char peerstr[INET6_ADDRSTRLEN];

        gt_toaddr(bindstr, sizeof(bindstr),
                  (struct sockaddr *)&res.path_status.local_addr);
        gt_toaddr(publstr, sizeof(publstr),
                  (struct sockaddr *)&res.path_status.r_addr);
        gt_toaddr(peerstr, sizeof(peerstr),
                  (struct sockaddr *)&res.path_status.addr);

        const char *statestr = NULL;

        switch (res.path_status.state) {
            case MUD_UP:     statestr = "UP";     break;
            case MUD_BACKUP: statestr = "BACKUP"; break;
            case MUD_DOWN:   statestr = "DOWN";   break;
            default:         return -2;
        }

        printf("path %s\n"
               "  bind:     %s port %"PRIu16"\n"
               "  public:   %s port %"PRIu16"\n"
               "  peer:     %s port %"PRIu16"\n"
               "  mtu:      %zu bytes\n"
               "  rtt:      %.3f ms\n"
               "  rttvar:   %.3f ms\n"
               "  upload:   %"PRIu64" bytes/s (max: %"PRIu64")\n"
               "  download: %"PRIu64" bytes/s (max: %"PRIu64")\n"
               "  output:   %"PRIu64" packets\n"
               "  input:    %"PRIu64" packets\n",
               statestr,
               bindstr[0] ? bindstr : "-",
               gt_get_port((struct sockaddr *)&res.path_status.local_addr),
               publstr[0] ? publstr : "-",
               gt_get_port((struct sockaddr *)&res.path_status.r_addr),
               peerstr[0] ? peerstr : "-",
               gt_get_port((struct sockaddr *)&res.path_status.addr),
               res.path_status.mtu.ok,
               res.path_status.rtt/(double)1e3,
               res.path_status.rttvar/(double)1e3,
               res.path_status.r_rate,
               res.path_status.r_ratemax,
               res.path_status.recv.rate,
               res.path_status.recv.ratemax,
               res.path_status.send.total,
               res.path_status.recv.total);
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

    int fd = ctl_connect(GT_RUNDIR, dev);

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
