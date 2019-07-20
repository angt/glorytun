#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../argz/argz.h"

static void
gt_path_print_status(struct mud_path *path, int term)
{
    char bindstr[INET6_ADDRSTRLEN];
    char publstr[INET6_ADDRSTRLEN];
    char peerstr[INET6_ADDRSTRLEN];

    gt_toaddr(bindstr, sizeof(bindstr),
            (struct sockaddr *)&path->local_addr);
    gt_toaddr(publstr, sizeof(publstr),
            (struct sockaddr *)&path->r_addr);
    gt_toaddr(peerstr, sizeof(peerstr),
            (struct sockaddr *)&path->addr);

    const char *statestr = NULL;

    switch (path->state) {
        case MUD_UP:     statestr = "UP";     break;
        case MUD_BACKUP: statestr = "BACKUP"; break;
        case MUD_DOWN:   statestr = "DOWN";   break;
        default:         return;
    }

    const char *statusstr = path->ok ? "OK" : "DEGRADED";

    printf(term ? "path %s\n"
            "  status:   %s\n"
            "  bind:     %s port %"PRIu16"\n"
            "  public:   %s port %"PRIu16"\n"
            "  peer:     %s port %"PRIu16"\n"
            "  mtu:      %zu bytes\n"
            "  rtt:      %.3f ms\n"
            "  rttvar:   %.3f ms\n"
            "  rate tx:  %"PRIu64" bytes/sec\n"
            "  rate rx:  %"PRIu64" bytes/sec\n"
            "  total tx: %"PRIu64" packets\n"
            "  total rx: %"PRIu64" packets\n"
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
            "\n",
        statestr,
        statusstr,
        bindstr[0] ? bindstr : "-",
        gt_get_port((struct sockaddr *)&path->local_addr),
        publstr[0] ? publstr : "-",
        gt_get_port((struct sockaddr *)&path->r_addr),
        peerstr[0] ? peerstr : "-",
        gt_get_port((struct sockaddr *)&path->addr),
        path->mtu.ok,
        (double)path->rtt.val / 1e3,
        (double)path->rtt.var / 1e3,
        path->rate_tx,
        path->rate_rx,
        path->send.total,
        path->recv.total);
}

static int
gt_path_status(int fd)
{
    struct ctl_msg req = {
        .type = CTL_PATH_STATUS,
    }, res = {0};

    if (send(fd, &req, sizeof(struct ctl_msg), 0) == -1)
        return -1;

    struct mud_path path[MUD_PATH_MAX];
    int count = 0;

    while (1) {
        if (recv(fd, &res, sizeof(struct ctl_msg), 0) == -1)
            return -1;

        if (res.type != req.type)
            return -2;

        if (res.ret == EAGAIN) {
            memcpy(&path[count], &res.path_status, sizeof(struct mud_path));
            count++;
        } else if (res.ret) {
            errno = res.ret;
            return -1;
        } else break;
    }

    int term = isatty(1);

    for (int i = 0; i < count; i++)
        gt_path_print_status(&path[i], term);

    return 0;
}

int
gt_path(int argc, char **argv)
{
    const char *dev = NULL;

    struct ctl_msg req = {
        .type = CTL_STATE,
    }, res = {0};

    struct argz ratez[] = {
        {"tx", "BYTES/SEC", &req.path.rate_tx, argz_bytes},
        {"rx", "BYTES/SEC", &req.path.rate_rx, argz_bytes},
        {NULL}};

    struct argz pathz[] = {
        {NULL, "IPADDR", &req.path.addr, argz_addr},
        {"dev", "NAME", &dev, argz_str},
        {"up|backup|down", NULL, NULL, argz_option},
        {"rate", NULL, &ratez, argz_option},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    int fd = ctl_connect(GT_RUNDIR, dev);

    if (fd < 0) {
        switch (fd) {
        case -1:
            perror("path");
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

    int ret = 0;

    if (!req.path.addr.ss_family) {
        ret = gt_path_status(fd);

        if (ret == -2)
            gt_log("bad reply from server\n");
    } else {
        req.path.state = MUD_EMPTY;

        if (argz_is_set(pathz, "up")) {
            req.path.state = MUD_UP;
        } else if (argz_is_set(pathz, "backup")) {
            req.path.state = MUD_BACKUP;
        } else if (argz_is_set(pathz, "down")) {
            req.path.state = MUD_DOWN;
        }

        ret = ctl_reply(fd, &res, &req);
    }

    if (ret == -1)
        perror("path");

    ctl_delete(fd);

    return !!ret;
}
