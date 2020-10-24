#include "common.h"
#include "ctl.h"
#include "argz.h"

#include <stdarg.h>

enum gt_path_show {
    gt_path_show_mtu  = 1,
    gt_path_show_rtt  = 2,
    gt_path_show_stat = 3,
};

struct gt_path_hdr {
    int m;
    char v[MUD_PATH_MAX + 1][INET6_ADDRSTRLEN + 6];
};

static void
gt_path_print(struct gt_path_hdr *h, int i, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(h->v[i], sizeof(h->v[i]), fmt, ap);
    va_end(ap);

    if (ret <= 0 || (size_t)ret >= sizeof(h->v[i])) {
        memcpy(h->v[i], "-", 2);
    } else if (h->m < ret) {
        h->m = ret;
    }
}

static void
gt_path_conf(struct ctl_msg *res)
{
    const char *state = NULL;
    char local[INET6_ADDRSTRLEN];
    char remote[INET6_ADDRSTRLEN];
    char beat[32];
    char tx[32], rx[32];

    switch (res->path.conf.state) {
        case MUD_PASSIVE: state = "passive"; break;
        case MUD_UP:      state = "up";      break;
        case MUD_DOWN:    state = "down";    break;
        default:          return;
    }
    gt_toaddr(local, sizeof(local), &res->path.conf.local);
    gt_toaddr(remote, sizeof(remote), &res->path.conf.remote);

    if (gt_totime(beat, sizeof(beat), res->path.conf.beat / 1000))
        return;

    if (gt_torate(tx, sizeof(tx), res->path.conf.tx_max_rate * 8) ||
        gt_torate(rx, sizeof(rx), res->path.conf.rx_max_rate * 8))
        return;

    printf("path dev %s addr %s to addr %s port %"PRIu16" "
           "set %s pref %u beat %s losslimit %u%% rate %s tx %s rx %s\n",
            res->tun_name, local,
            remote, gt_get_port(&res->path.conf.remote),
            state, res->path.conf.pref, beat,
            res->path.conf.loss_limit * 100U / 255U,
            res->path.conf.fixed_rate ? "fixed" : "auto",
            tx, rx);
}

static int
gt_path_status(int fd, enum gt_path_show show)
{
    struct ctl_msg res = {0};
    enum {
        type,   local,  remote, public, rtt,    rttvar,
        txloss, txrate, txtot,  rxloss, rxrate, rxtot,
        status, mtu,    mprobe, mmin,   mmax,   mlast,
    };
    struct gt_path_hdr hdr[] = {
        [type  ] = {4, .v[0] = "#"        },
        [local ] = {5, .v[0] = "LOCAL"    },
        [remote] = {6, .v[0] = "REMOTE"   },
        [public] = {6, .v[0] = "PUBLIC"   },
        [status] = {6, .v[0] = "STATUS"   },
        [rtt   ] = {3, .v[0] = "RTT"      },
        [rttvar] = {6, .v[0] = "RTT-VAR"  },
        [mtu   ] = {3, .v[0] = "MTU"      },
        [mprobe] = {9, .v[0] = "MTU-PROBE"},
        [mmin  ] = {7, .v[0] = "MTU-MIN"  },
        [mmax  ] = {7, .v[0] = "MTU-MAX"  },
        [mlast ] = {8, .v[0] = "MTU-LAST" },
        [txloss] = {7, .v[0] = "TX-LOSS"  },
        [txrate] = {7, .v[0] = "TX-RATE"  },
        [txtot ] = {8, .v[0] = "TX-TOTAL" },
        [rxloss] = {7, .v[0] = "RX-LOSS"  },
        [rxrate] = {7, .v[0] = "RX-RATE"  },
        [rxtot ] = {8, .v[0] = "RX-TOTAL" },
    };
    for (unsigned i = 1; i <= MUD_PATH_MAX; i++) {
        if (recv(fd, &res, sizeof(res), 0) == -1)
            return -1;

        if (res.type != CTL_PATH_STATUS) {
            errno = EBADMSG;
            return -1;
        }
        if (!res.ret)
            break;

        if (res.ret != EAGAIN) {
            errno = res.ret;
            return -1;
        }
        char tmp[INET6_ADDRSTRLEN];
        memcpy(hdr[type].v[i], "path", 5);

        const char *path_status;
        switch (res.path.status) {
            case MUD_DELETING: path_status = "deleting"; break;
            case MUD_PROBING:  path_status = "probing";  break;
            case MUD_DEGRADED: path_status = "degraded"; break;
            case MUD_LOSSY:    path_status = "lossy";    break;
            case MUD_WAITING:  path_status = "waiting";  break;
            case MUD_READY:    path_status = "ready";    break;
            case MUD_RUNNING:  path_status = "running";  break;
            default:           return -1;
        }

        gt_toaddr(tmp, sizeof(tmp), &res.path.conf.local);
        gt_path_print(&hdr[local ], i, "%s", tmp);

        gt_toaddr(tmp, sizeof(tmp), &res.path.conf.remote);
        gt_path_print(&hdr[remote], i, "%s.%"PRIu16, tmp,
                      gt_get_port(&res.path.conf.remote));

        if (gt_toaddr(tmp, sizeof(tmp), &res.path.remote)) {
            gt_path_print(&hdr[public], i, "unknown", tmp);
        } else {
            gt_path_print(&hdr[public], i, "%s.%"PRIu16, tmp,
                          gt_get_port(&res.path.remote));
        }

        gt_path_print(&hdr[status], i,      "%s", path_status);
        gt_path_print(&hdr[mtu   ], i,     "%zu", res.path.mtu.ok);
        gt_path_print(&hdr[mprobe], i,     "%zu", res.path.mtu.probe);
        gt_path_print(&hdr[mmin  ], i,     "%zu", res.path.mtu.min);
        gt_path_print(&hdr[mmax  ], i,     "%zu", res.path.mtu.max);
        gt_path_print(&hdr[mlast ], i,     "%zu", res.path.mtu.last);
        gt_path_print(&hdr[rtt   ], i,    "%.3f", res.path.rtt.val / 1e3);
        gt_path_print(&hdr[rttvar], i,    "%.3f", res.path.rtt.var / 1e3);
        gt_path_print(&hdr[txloss], i,   "%3.2f", res.path.tx.loss * 100 / 255.0);
        gt_path_print(&hdr[rxloss], i,   "%3.2f", res.path.rx.loss * 100 / 255.0);
        gt_path_print(&hdr[txrate], i, "%"PRIu64, res.path.tx.rate);
        gt_path_print(&hdr[rxrate], i, "%"PRIu64, res.path.rx.rate);
        gt_path_print(&hdr[txtot ], i, "%"PRIu64, res.path.tx.total);
        gt_path_print(&hdr[rxtot ], i, "%"PRIu64, res.path.rx.total);
    }
    for (unsigned i = 0; i <= MUD_PATH_MAX; i++) {
        if (hdr[type].v[i][0]) switch (show) {
        case gt_path_show_mtu:
            printf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
                    hdr[type  ].m, hdr[type  ].v[i],
                    hdr[local ].m, hdr[local ].v[i],
                    hdr[remote].m, hdr[remote].v[i],
                    hdr[mtu   ].m, hdr[mtu   ].v[i],
                    hdr[mprobe].m, hdr[mprobe].v[i],
                    hdr[mmin  ].m, hdr[mmin  ].v[i],
                    hdr[mmax  ].m, hdr[mmax  ].v[i],
                    hdr[mlast ].m, hdr[mlast ].v[i]);
            break;
        case gt_path_show_rtt:
            printf("%-*s  %-*s  %-*s  %-*s  %-*s\n",
                    hdr[type  ].m, hdr[type  ].v[i],
                    hdr[local ].m, hdr[local ].v[i],
                    hdr[remote].m, hdr[remote].v[i],
                    hdr[rtt   ].m, hdr[rtt   ].v[i],
                    hdr[rttvar].m, hdr[rttvar].v[i]);
            break;
        case gt_path_show_stat:
            printf("%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
                    hdr[type  ].m, hdr[type  ].v[i],
                    hdr[local ].m, hdr[local ].v[i],
                    hdr[remote].m, hdr[remote].v[i],
                    hdr[txrate].m, hdr[txrate].v[i],
                    hdr[rxrate].m, hdr[rxrate].v[i],
                    hdr[txloss].m, hdr[txloss].v[i],
                    hdr[rxloss].m, hdr[rxloss].v[i]);
            break;
        default:
            printf("%-*s  %-*s  %-*s  %-*s  %-*s\n",
                    hdr[type  ].m, hdr[type  ].v[i],
                    hdr[local ].m, hdr[local ].v[i],
                    hdr[remote].m, hdr[remote].v[i],
                    hdr[status].m, hdr[status].v[i],
                    hdr[public].m, hdr[public].v[i]);
        }
    }
    return 0;
}

int
gt_path(int argc, char **argv, void *data)
{
    struct argz_ull tx = {.suffix = argz_size_suffix};
    struct argz_ull rx = {.suffix = argz_size_suffix};

    struct argz ratez[] = {
        {"fixed", "Fixed rate",                            .grp = 2},
        {"auto",  "Dynamic rate detection (experimental)", .grp = 2},
        {"tx",    "Maximum transmission rate",   argz_ull,      &tx},
        {"rx",    "Maximum reception rate",      argz_ull,      &rx},
        {0}};

    struct argz_ull beat = {.suffix = argz_time_suffix};
    struct argz_ull pref = {.max = 0xFF >> 1};
    struct argz_ull loss = {.max = 100, .suffix = gt_argz_percent_suffix};

    struct argz setz[] = {
        {"up",        "Enable path",                .grp = 2},
        {"down",      "Disable path",               .grp = 2},
        {"rate",      "Rate limit properties",  argz, &ratez},
        {"beat",      "Internal beat rate", argz_ull,  &beat},
        {"pref",      "Path preference",    argz_ull,  &pref},
        {"losslimit", "Disable lossy path", argz_ull,  &loss},
        {0}};

    struct argz showz[] = {
        {"mtu",  "Show MTU probes",       .grp = 2},
        {"rtt",  "Show RTT and RTT var",  .grp = 2},
        {"stat", "Show TX/RX statistics", .grp = 2},
        {0}};

    struct gt_argz_addr local = {0};
    struct gt_argz_addr remote = {0};
    const char *dev = NULL;

    struct argz z[] = {
        {"dev",  "Select tunnel device",       gt_argz_dev,       &dev},
        {"addr", "Select path by local addr",  gt_argz_addr_ip, &local},
        {"to",   "Select path by remote addr", gt_argz_addr,   &remote},
        {"set",  "Change path properties",     argz,  &setz,  .grp = 1},
        {"show", "Show path status",           argz, &showz,  .grp = 1},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }
    int ret = 0;

    if (argz_is_set(z, "set")) {
        struct ctl_msg req = {
            .type = CTL_PATH_CONF,
            .path.conf = {
                .local       = local.sock,
                .remote      = remote.sock,
                .state       = MUD_EMPTY,
                .tx_max_rate = tx.value,
                .rx_max_rate = rx.value,
                .beat        = beat.value,
                .pref        = argz_is_set(setz, "pref")
                             ? (pref.value << 1) | 1 : 0,
                .loss_limit  = loss.value * 255 / 100,
            },
        }, res = {0};

        if (argz_is_set(setz, "up"))
            req.path.conf.state = MUD_UP;

        if (argz_is_set(setz, "down"))
            req.path.conf.state = MUD_DOWN;

        if (argz_is_set(ratez, "fixed"))
            req.path.conf.fixed_rate = 3;

        if (argz_is_set(ratez, "auto"))
            req.path.conf.fixed_rate = 1;

        ret = ctl_reply(fd, &res, &req);

        if (!ret)
            gt_path_conf(&res);
    } else {
        struct ctl_msg req = {
            .type = CTL_PATH_STATUS,
            .path.conf = {
                .local  = local.sock,
                .remote = remote.sock,
            },
        };
        enum gt_path_show show = 0;

        if (argz_is_set(showz, "rtt"))
            show = gt_path_show_rtt;

        if (argz_is_set(showz, "mtu"))
            show = gt_path_show_mtu;

        if (argz_is_set(showz, "stat"))
            show = gt_path_show_stat;

        if (send(fd, &req, sizeof(req), 0) != sizeof(req))
            ret = -1;

        if (!ret)
            ret = gt_path_status(fd, show);
    }
    if (ret == -1 && errno)
        perror("path");

    ctl_delete(fd);

    return ret;
}
