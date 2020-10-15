#include "common.h"
#include "ctl.h"
#include "argz.h"

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

    switch (path->conf.state) {
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
gt_path_print_all(int fd, struct sockaddr_storage *local_addr,
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
gt_path(int argc, char **argv, void *data)
{
    struct argz_ull rate_tx = {.suffix = argz_size_suffix};
    struct argz_ull rate_rx = {.suffix = argz_size_suffix};

    struct argz ratez[] = {
        {"fixed", "Fixed rate",                            .grp = 2},
        {"auto",  "Dynamic rate detection (experimental)", .grp = 2},
        {"tx",    "Maximum transmission rate",   argz_ull, &rate_tx},
        {"rx",    "Maximum reception rate",      argz_ull, &rate_rx},
        {0}};

    struct argz_ull set_beat = {.suffix = argz_time_suffix};
    struct argz_ull set_loss = {.min = 0, .max = 100};

    struct argz setz[] = {
        {"up",        "Enable path as primary",        .grp = 2},
        {"backup",    "Enable path as secondary",      .grp = 2},
        {"down",      "Disable path",                  .grp = 2},
        {"rate",      "Rate limit properties",  argz,    &ratez},
        {"beat",      "Internal beat rate", argz_ull, &set_beat},
        {"losslimit", "Disable lossy path", argz_ull, &set_loss},
        {0}};

    struct gt_argz_addr from = {0};
    struct gt_argz_addr to = {0};
    const char *dev = NULL;

    struct argz z[] = {
        {"dev",  "Select tunnel device",               gt_argz_dev,   &dev},
        {"from", "Select path by source address",      gt_argz_addr, &from},
        {"to",   "Select path by destination address", gt_argz_addr,   &to},
        {"set",  "Change path properties",             argz,         &setz},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }

    struct ctl_msg req = {
        .type = CTL_STATE,
        .path = {
            .local_addr = from.ss,
            .addr = to.ss,
            .conf = {
                .state       = MUD_EMPTY,
                .tx_max_rate = rate_tx.value,
                .rx_max_rate = rate_rx.value,
                .beat        = set_beat.value,
                .loss_limit  = set_loss.value * 255 / 100,
            },
        },
    }, res = {0};

    int ret = 0;

    if (argz_is_set(z, "set")) {
        if (!from.ss.ss_family) { // XXX
            gt_log("please specify a path\n");
            return 1;
        }

        if (argz_is_set(setz, "up")) {
            req.path.conf.state = MUD_UP;
        } else if (argz_is_set(setz, "backup")) {
            req.path.conf.state = MUD_BACKUP;
        } else if (argz_is_set(setz, "down")) {
            req.path.conf.state = MUD_DOWN;
        }

        if (argz_is_set(ratez, "fixed")) {
            req.path.conf.fixed_rate = 3;
        } else if (argz_is_set(ratez, "auto")) {
            req.path.conf.fixed_rate = 1;
        }

        ret = ctl_reply(fd, &res, &req);
    }

    if (!ret)
        ret = gt_path_print_all(fd, &req.path.local_addr, &req.path.addr);

    if (ret == -1)
        perror("path");

    ctl_delete(fd);

    return -!!ret;
}
