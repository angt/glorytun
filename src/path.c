#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <sys/socket.h>

#include "../argz/argz.h"

int
gt_path(int argc, char **argv)
{
    const char *dev = "tun0";
    struct sockaddr_storage addr = { 0 };

    struct argz actionz[] = {
        {NULL, "IPADDR", &addr, argz_addr},
        {NULL}};

    struct argz pathz[] = {
        {"dev", "NAME", &dev, argz_str},
        {"up|down", NULL, &actionz, argz_option},
        {NULL}};

    if (argz(pathz, argc, argv))
        return 1;

    struct ctl_msg req, res = {0};

    if (argz_is_set(pathz, "up")) {
        req = (struct ctl_msg){
            .type = CTL_PATH_ADD,
            .path_addr = addr,
        };
    } else if (argz_is_set(pathz, "down")) {
        req = (struct ctl_msg){
            .type = CTL_PATH_DEL,
            .path_addr = addr,
        };
    } else {
        gt_log("nothing to do..\n");
        return 0;
    }

    int fd = ctl_create("/run/" PACKAGE_NAME, NULL);

    if (fd == -1) {
        perror("ctl_create");
        return 1;
    }

    if (ctl_connect(fd, "/run/" PACKAGE_NAME, dev) == -1) {
        gt_log("couldn't connect to %s\n", dev);
        ctl_delete(fd);
        return 1;
    }

    int ret = 0;

    if (ctl_reply(fd, &res, &req)) {
        perror(dev);
        ret = 1;
    }

    ctl_delete(fd);

    return ret;
}
