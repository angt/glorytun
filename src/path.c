#include "common.h"
#include "ctl.h"

#include <stdio.h>

#include "../argz/argz.h"

static void
gt_path_print(struct mud_path *path, int term)
{
    const char *statestr = NULL;
    char bindstr[INET6_ADDRSTRLEN];
    char peerstr[INET6_ADDRSTRLEN];
    char beatstr[32];
    char txstr[32], rxstr[32];

    switch (path->state) {
        case MUD_UP:     statestr = "up";     break;
        case MUD_BACKUP: statestr = "backup"; break;
        case MUD_DOWN:   statestr = "down";   break;
        default:         return;
    }

    if (gt_toaddr(bindstr, sizeof(bindstr),
                  (struct sockaddr *)&path->local_addr) ||
        gt_toaddr(peerstr, sizeof(peerstr),
                  (struct sockaddr *)&path->addr))
        return;

    if (gt_totime(beatstr, sizeof(beatstr), path->conf.beat / 1000))
        return;

    if (gt_torate(txstr, sizeof(txstr), path->conf.tx_max_rate * 8) ||
        gt_torate(rxstr, sizeof(rxstr), path->conf.rx_max_rate * 8))
        return;

    printf(term ? "path %s %s to %s port %"PRIu16" losslimit %u%% beat %s "
                  "rate %s tx %s rx %s\n"
                : "path %s %s %s %"PRIu16" %u %s %s %s %s\n",
            statestr, bindstr, peerstr,
            gt_get_port((struct sockaddr *)&path->addr),
            path->conf.loss_limit * 100U / 255U,
            beatstr,
            path->conf.fixed_rate ? "fixed" : "auto",
            txstr, rxstr);
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
gt_path_cmp_port(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 1;

    if (a->ss_family == AF_INET) {
        struct sockaddr_in *A = (struct sockaddr_in *)a;
        struct sockaddr_in *B = (struct sockaddr_in *)b;
        return ((memcmp(&A->sin_port, &B->sin_port, sizeof(A->sin_port))));
    }

    if (a->ss_family == AF_INET6) {
        struct sockaddr_in6 *A = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *B = (struct sockaddr_in6 *)b;
        return ((memcmp(&A->sin6_port, &B->sin6_port, sizeof(A->sin6_port))));
    }

    return 1;
}

static int
gt_path_print_all(int fd, enum mud_state state,
                  struct sockaddr_storage *local_addr,
                  struct sockaddr_storage *addr)
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

    if (!term)
        printf("# STATE LOCAL_ADDR ADDR PORT LOSSLIMIT BEAT RATE TX RX\n");

    for (int i = 0; i < count; i++) {
        if (state && path[i].state != state)
            continue;
        if (local_addr->ss_family &&
            gt_path_cmp_addr(local_addr, &path[i].local_addr))
            continue;
        if (addr->ss_family &&
            (gt_path_cmp_addr(addr, &path[i].addr) ||
             gt_path_cmp_port(addr, &path[i].addr)))
            continue;
        gt_path_print(&path[i], term);
    }

    return 0;
}

int
gt_path(int argc, char **argv)
{
    const char *dev = NULL;
    unsigned int loss_limit = 0;
    unsigned short peer_port = 0;

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

    struct argz setz[] = {
        {"up|backup|down", NULL, NULL, argz_option},
        {"rate", NULL, &ratez, argz_option},
        {"beat", "SECONDS", &req.path.beat, argz_time},
        {"losslimit", "PERCENT", &loss_limit, argz_percent},
        {NULL}};

    struct argz toz[] = {
        {NULL, "IPADDR", &req.path.addr, argz_addr},
        {NULL, "PORT", &peer_port, argz_ushort},
        {NULL}};

    struct argz pathz[] = {
        {NULL, "IPADDR", &req.path.local_addr, argz_addr},
        {"to", NULL, &toz, argz_option},
        {"dev", "NAME", &dev, argz_str},
        {"set", NULL, &setz, argz_option},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    gt_set_port((struct sockaddr *)&req.path.addr, peer_port);

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return 1;
    }

    int ret = 0;

    if (argz_is_set(pathz, "set")) {
        if (!req.path.local_addr.ss_family) { // XXX
            gt_log("please specify a path\n");
            return 1;
        }

        if (argz_is_set(setz, "up")) {
            req.path.state = MUD_UP;
        } else if (argz_is_set(setz, "backup")) {
            req.path.state = MUD_BACKUP;
        } else if (argz_is_set(setz, "down")) {
            req.path.state = MUD_DOWN;
        }

        req.path.loss_limit = loss_limit * 255 / 100;

        if (argz_is_set(ratez, "fixed")) {
            req.path.fixed_rate = 3;
        } else if (argz_is_set(ratez, "auto")) {
            req.path.fixed_rate = 1;
        }

        ret = ctl_reply(fd, &res, &req);
    }

    if (!ret)
        ret = gt_path_print_all(fd, req.path.state,
                                &req.path.local_addr,
                                &req.path.addr);

    if (ret == -1)
        perror("path");

    ctl_delete(fd);

    return !!ret;
}
