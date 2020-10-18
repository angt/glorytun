#include "common.h"
#include "ctl.h"
#include "argz.h"

int
gt_set(int argc, char **argv, void *data)
{
    const char *dev = NULL;
    struct argz_ull kx = {.suffix = argz_time_suffix};
    struct argz_ull tt = {.suffix = argz_time_suffix};
    struct argz_ull ka = {.suffix = argz_time_suffix};

    struct argz z[] = {
        {"dev",           "Tunnel device",       gt_argz_dev, &dev},
        {"kxtimeout",     "Key rotation timeout",   argz_ull,  &kx},
        {"timetolerance", "Clock sync tolerance",   argz_ull,  &tt},
        {"keepalive",     "Keep alive timeout",     argz_ull,  &ka},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    struct ctl_msg req = {
        .type = CTL_CONF,
        .conf = {
            .kxtimeout     = kx.value * UINT64_C(1000),
            .timetolerance = tt.value * UINT64_C(1000),
            .keepalive     = ka.value * UINT64_C(1000),
        },
    }, res = {0};

    int fd = ctl_connect(dev);

    if (fd < 0) {
        ctl_explain_connect(fd);
        return -1;
    }
    int ret = ctl_reply(fd, &res, &req);

    if (!ret) {
        char t0[32], t1[32], t2[32];
        gt_totime(t0, sizeof(t0), res.conf.kxtimeout     / 1000);
        gt_totime(t1, sizeof(t1), res.conf.timetolerance / 1000);
        gt_totime(t2, sizeof(t2), res.conf.keepalive     / 1000);

        printf("set dev %s kxtimeout %s timetolerance %s keepalive %s\n",
                res.tun_name, t0, t1, t2);
    }
    if (ret == -1 && errno)
        perror("set");

    ctl_delete(fd);

    return ret;
}
