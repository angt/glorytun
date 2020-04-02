#include "common.h"
#include "ctl.h"

#include <stdio.h>

#include "../argz/argz.h"

static void
gt_path_print(struct mud_path *path, int term)
{
    const char *statestr = NULL;
    char bindstr[INET6_ADDRSTRLEN];

    switch (path->state) {
        case MUD_UP:     statestr = "up";     break;
        case MUD_BACKUP: statestr = "backup"; break;
        case MUD_DOWN:   statestr = "down";   break;
        default:         return;
    }

    if (gt_toaddr(bindstr, sizeof(bindstr),
                  (struct sockaddr *)&path->local_addr))
        return;

    printf(term ? "path %s %s losslimit %u%% beat %"PRIu64"ms "
                  "rate %s tx %"PRIu64" rx %"PRIu64"\n"
                : "path %s %s %u %"PRIu64" %s %"PRIu64" %"PRIu64"\n",
            statestr, bindstr,
            path->conf.loss_limit * 100U / 255U,
            path->conf.beat / 1000,
            path->conf.fixed_rate ? "fixed" : "auto",
            path->conf.tx_max_rate,
            path->conf.rx_max_rate);
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
gt_path_print_all(int fd, enum mud_state state, struct sockaddr_storage *addr)
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
        printf("# STATE ADDR LOSSLIMIT BEAT RATE TX RX\n");

    for (int i = 0; i < count; i++) {
        if (state && path[i].state != state)
            continue;
        if (addr->ss_family && gt_path_cmp_addr(addr, &path[i].local_addr))
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
        {"beat", "SECONDS", &req.path.beat, argz_time},
        {"losslimit", "PERCENT", &loss_limit, argz_percent},
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
        ret = gt_path_print_all(fd, req.path.state, &req.path.addr);

    if (ret == -1)
        perror("path");

    ctl_delete(fd);

    return !!ret;
}
