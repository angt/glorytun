#include "common.h"
#include "ctl.h"
#include "argz.h"

static void
gt_show_error(const char *name, struct mud_error *err)
{
    if (!err->count)
        return;

    char addr[INET6_ADDRSTRLEN];
    gt_toaddr(addr, sizeof(addr), &err->addr);

    printf("error %s count %"PRIu64" from %s.%"PRIu16"\n",
            name, err->count, addr, gt_get_port(&err->addr));
}

static int
gt_show_errors(int fd)
{
    struct ctl_msg req = {
        .type = CTL_ERRORS,
    }, res = {0};

    if (ctl_reply(fd, &res, &req))
        return -1;

    gt_show_error("decrypt",   &res.errors.decrypt);
    gt_show_error("clocksync", &res.errors.clocksync);
    gt_show_error("keyx",      &res.errors.keyx);

    return 0;
}

static int
gt_show_status(int fd)
{
    struct ctl_msg req = {
        .type = CTL_STATUS,
    }, res = {0};

    if (ctl_reply(fd, &res, &req))
        return -1;

    char local[INET6_ADDRSTRLEN];
    char remote[INET6_ADDRSTRLEN];

    gt_toaddr(local, sizeof(local), &res.status.local);
    gt_toaddr(remote, sizeof(remote), &res.status.remote);

    printf("tunnel %s\n"
           "local  %s.%"PRIu16"\n"
           "remote %s.%"PRIu16"\n"
           "pid    %li\n"
           "mtu    %zu\n"
           "cipher %s\n",
            res.tun_name,
            local, gt_get_port(&res.status.local),
            remote, gt_get_port(&res.status.remote),
            res.status.pid,
            res.status.mtu,
            GT_CIPHER(res.status.cipher));

    return 0;
}

int
gt_show(int argc, char **argv, void *data)
{
    const char *dev = NULL;

    struct argz z[] = {
        {"dev",    "Tunnel device", gt_argz_dev, &dev},
        {"errors", "Show tunnel errors"              },
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }
    int ret = argz_is_set(z, "errors") ? gt_show_errors(fd)
                                       : gt_show_status(fd);
    if (ret == -1 && errno)
        perror("show");

    ctl_delete(fd);

    return ret;
}
