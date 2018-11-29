#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../argz/argz.h"

static int
gt_path_status(int fd)
{
    struct ctl_msg req = {
        .type = CTL_PATH_STATUS,
    }, res = {0};

    if (send(fd, &req, sizeof(struct ctl_msg), 0) == -1)
        return -1;

    int term = isatty(1);

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

        const char *statusstr = "DEGRADED";

        if (res.path_status.ok)
            statusstr = "OK";

        printf(term ? "path %s\n"
                      "  status:   %s\n"
                      "  bind:     %s port %"PRIu16"\n"
                      "  public:   %s port %"PRIu16"\n"
                      "  peer:     %s port %"PRIu16"\n"
                      "  mtu:      %zu bytes\n"
                      "  rtt:      %.3f ms\n"
                      "  rttvar:   %.3f ms\n"
                      "  upload:   %"PRIu64" bytes/s (max: %"PRIu64")\n"
                      "  download: %"PRIu64" bytes/s (max: %"PRIu64")\n"
                      "  output:   %"PRIu64" packets\n"
                      "  input:    %"PRIu64" packets\n"
                    : "path %s %s"
                      " %s %"PRIu16
                      " %s %"PRIu16
                      " %s %"PRIu16
                      " %zu"
                      " %.3f %.3f"
                      " %"PRIu64
                      " %"PRIu64
                      " %"PRIu64
                      " %"PRIu64
                      " %"PRIu64
                      " %"PRIu64
                      "\n",
            statestr,
            statusstr,
            bindstr[0] ? bindstr : "-",
            gt_get_port((struct sockaddr *)&res.path_status.local_addr),
            publstr[0] ? publstr : "-",
            gt_get_port((struct sockaddr *)&res.path_status.r_addr),
            peerstr[0] ? peerstr : "-",
            gt_get_port((struct sockaddr *)&res.path_status.addr),
            res.path_status.mtu.ok,
            res.path_status.rtt.val / 1e3,
            res.path_status.rtt.var / 1e3,
            res.path_status.r_rate * 10,
            res.path_status.r_ratemax * 10,
            res.path_status.rate.val * 10,
            res.path_status.recv.ratemax * 10,
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

    if (fd < 0) {
        switch (fd) {
        case -1:
            perror("path");
            break;
        case -2:
            gt_log("no device\n");
            break;
        case -3:
            gt_log("please choose a device\n");
            break;
        default:
            gt_log("couldn't connect\n");
        }
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

    return !!ret;
}
