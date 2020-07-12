#include "common.h"
#include "ctl.h"

#include <stdio.h>

#include "../argz/argz.h"

static void
gt_path_print(struct mud_path *path, int status, int term)
{
    const char *statestr = NULL;
    char bindstr[INET6_ADDRSTRLEN];
    char publstr[INET6_ADDRSTRLEN];
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
                  (struct sockaddr *)&path->local_addr))
        return;

    if (gt_toaddr(publstr, sizeof(publstr),
                  (struct sockaddr *)&path->r_addr))
        return;

    if (gt_toaddr(peerstr, sizeof(peerstr),
                  (struct sockaddr *)&path->addr))
        return;

    if (gt_totime(beatstr, sizeof(beatstr), path->conf.beat / 1000))
        return;

    if (gt_torate(txstr, sizeof(txstr), path->conf.tx_max_rate * 8))
        return;

    if (gt_torate(rxstr, sizeof(rxstr), path->conf.rx_max_rate * 8))
        return;

    if (status) {
        printf(term ? "path %s\n"
                "  status:  %s\n"
                "  bind:    %s port %"PRIu16"\n"
                "  public:  %s port %"PRIu16"\n"
                "  peer:    %s port %"PRIu16"\n"
                "  mtu:     %zu\n"
                "  rtt:     %.3f ms\n"
                "  rttvar:  %.3f ms\n"
                "  rate:    %s\n"
                "  losslim: %u%%\n"
                "  beat:    %"PRIu64" ms\n"
                "  tx:\n"
                "    rate:  %"PRIu64" B/s\n"
                "    loss:  %"PRIu64"%%\n"
                "    total: %"PRIu64" packets\n"
                "  rx:\n"
                "    rate:  %"PRIu64" B/s\n"
                "    loss:  %"PRIu64"%%\n"
                "    total: %"PRIu64" packets\n"
                : "path %s %s"
                " %s %"PRIu16" %s %"PRIu16" %s %"PRIu16
                " %zu %.3f %.3f %s %u %"PRIu64
                " %"PRIu64" %"PRIu64" %"PRIu64
                " %"PRIu64" %"PRIu64" %"PRIu64
                "\n",
            statestr, path->ok ? "ok" : "degraded",
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
            path->conf.loss_limit * 100U / 255U,
            path->conf.beat / 1000,
            path->tx.rate,
            path->tx.loss * 100U / 255U,
            path->tx.total,
            path->rx.rate,
            path->rx.loss * 100U / 255U,
            path->rx.total);
    } else {
        printf(term ? "path %s %s losslimit %u%% beat %s "
                      "rate %s tx %s rx %s\n"
                    : "path %s %s %u %s %s %s %s\n",
            statestr, bindstr,
            path->conf.loss_limit * 100U / 255U,
            beatstr,
            path->conf.fixed_rate ? "fixed" : "auto",
            txstr, rxstr);
    }
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
gt_path_print_all(int fd, enum mud_state state, struct sockaddr_storage *addr, int status)
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

    if (!term && !status)
        printf("# STATE ADDR LOSSLIMIT BEAT RATE TX RX\n");
    else if (!term && status)
        printf("# STATE STATUS BIND PUBLIC PEER MTU RTT RTTVAR RATE LOSSLIM BEAT TXRATE TXLOSS TXTOTAL RXRATE RXLOSS RXTOTAL\n");

    for (int i = 0; i < count; i++) {
        if (state && path[i].state != state)
            continue;
        if (addr->ss_family && gt_path_cmp_addr(addr, &path[i].local_addr))
            continue;
        gt_path_print(&path[i], status, term);
    }

    return 0;
}

int
gt_path(int argc, char **argv)
{
    const char *dev = NULL;
    unsigned int loss_limit = 0;

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
        {"status", NULL, NULL, argz_option},
        {"rate", NULL, &ratez, argz_option},
        {"beat", "SECONDS", &req.path.beat, argz_time},
        {"losslimit", "PERCENT", &loss_limit, argz_percent},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return 1;
    }

    int set = argz_is_set(pathz, "rate")
           || argz_is_set(pathz, "beat")
           || argz_is_set(pathz, "losslimit");

    if (set && !req.path.addr.ss_family) {
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

    if (loss_limit)
        req.path.loss_limit = loss_limit * 255 / 100;

    if (argz_is_set(ratez, "fixed")) {
        req.path.fixed_rate = 3;
    } else if (argz_is_set(ratez, "auto")) {
        req.path.fixed_rate = 1;
    }

    int ret = 0;

    if (req.path.addr.ss_family && (req.path.state || set))
        ret = ctl_reply(fd, &res, &req);

    if (!ret)
        ret = gt_path_print_all(fd, req.path.state, &req.path.addr, argz_is_set(pathz, "status"));

    if (ret == -1)
        perror("path");

    ctl_delete(fd);

    return !!ret;
}
