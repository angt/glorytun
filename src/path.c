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

    printf(term ? "path %s\n"
            "  status:  %s\n"
            "  bind:    %s port %"PRIu16"\n"
            "  public:  %s port %"PRIu16"\n"
            "  peer:    %s port %"PRIu16"\n"
            "  mtu:     %zu bytes\n"
            "  rtt:     %.3f ms\n"
            "  rttvar:  %.3f ms\n"
            "  rate:    %s\n"
            "  tx:\n"
            "    rate:  %"PRIu64" bytes/sec\n"
            "    loss:  %"PRIu64" percent\n"
            "    total: %"PRIu64" packets\n"
            "  rx:\n"
            "    rate:  %"PRIu64" bytes/sec\n"
            "    loss:  %"PRIu64" percent\n"
            "    total: %"PRIu64" packets\n"
            : "path %s %s"
            " %s %"PRIu16" %s %"PRIu16" %s %"PRIu16
            " %zu %.3f %.3f"
            " %s"
            " %"PRIu64" %"PRIu64" %"PRIu64
            " %"PRIu64" %"PRIu64" %"PRIu64
            "\n",
        statestr,
        path->ok ? "OK" : "DEGRADED",
        bindstr[0] ? bindstr : "-",
        gt_get_port((struct sockaddr *)&path->local_addr),
        publstr[0] ? publstr : "-",
        gt_get_port((struct sockaddr *)&path->r_addr),
        peerstr[0] ? peerstr : "-",
        gt_get_port((struct sockaddr *)&path->addr),
        path->mtu.ok,
        (double)path->rtt.val / 1e3,
        (double)path->rtt.var / 1e3,
        path->conf.fixed_rate ? "fixed" : "auto",
        path->tx.rate,
        path->tx.loss * 100 / 255,
        path->tx.total,
        path->rx.rate,
        path->rx.loss * 100 / 255,
        path->rx.total);
}

static int
gt_path_cmp_addr(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 1;

    if (a->ss_family == AF_INET) {
        struct sockaddr_in *A = (struct sockaddr_in *)a;
        struct sockaddr_in *B = (struct sockaddr_in *)b;
        return ((memcmp(&A->sin_addr, &B->sin_addr, sizeof(A->sin_addr))));
    }

    if (a->ss_family == AF_INET6) {
        struct sockaddr_in6 *A = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *B = (struct sockaddr_in6 *)b;
        return ((memcmp(&A->sin6_addr, &B->sin6_addr, sizeof(A->sin6_addr))));
    }

    return 1;
}

static int
gt_path_status(int fd, enum mud_state state, struct sockaddr_storage *addr)
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

        if (res.type != req.type) {
            errno = EBADMSG;
            return -1;
        }

        if (res.ret == EAGAIN) {
            memcpy(&path[count], &res.path_status, sizeof(struct mud_path));
            count++;
        } else if (res.ret) {
            errno = res.ret;
            return -1;
        } else break;
    }

    int term = isatty(1);

    for (int i = 0; i < count; i++) {
        if ((state == MUD_EMPTY || path[i].state == state) &&
            (!addr->ss_family || !gt_path_cmp_addr(addr, &path[i].local_addr)))
            gt_path_print_status(&path[i], term);
    }

    return 0;
}

int
gt_path(int argc, char **argv)
{
    const char *dev = NULL;

    struct ctl_msg req = {
        .type = CTL_STATE,
        .path = {
            .state = MUD_EMPTY,
        },
    }, res = {0};

    struct argz ratez[] = {
        {"fixed|auto", NULL, NULL, argz_option},
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

    int fd = ctl_connect(dev);

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

    int set_rate = argz_is_set(pathz, "rate");

    if (set_rate && !req.path.addr.ss_family) {
        gt_log("please specify a path\n");
        return 1;
    }

    if (argz_is_set(pathz, "up")) {
        req.path.state = MUD_UP;
    } else if (argz_is_set(pathz, "backup")) {
        req.path.state = MUD_BACKUP;
    } else if (argz_is_set(pathz, "down")) {
        req.path.state = MUD_DOWN;
    }

    if (argz_is_set(ratez, "fixed")) {
        req.path.fixed_rate = 3;
    } else if (argz_is_set(ratez, "auto")) {
        req.path.fixed_rate = 1;
    }

    int ret;

    if (!req.path.addr.ss_family ||
        (req.path.state == MUD_EMPTY && !set_rate)) {
        ret = gt_path_status(fd, req.path.state, &req.path.addr);
    } else {
        ret = ctl_reply(fd, &res, &req);
    }

    if (ret == -1)
        perror("path");

    ctl_delete(fd);

    return !!ret;
}
