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
    const char *addr = NULL;

    struct argz actionz[] = {
        {NULL, "IPADDR", &addr, argz_str},
        {}};

    struct argz pathz[] = {
        {"dev", "NAME", &dev, argz_str},
        {"up|down", NULL, &actionz, argz_option},
        {}};

    if (argz(pathz, argc, argv))
        return 1;

    struct ctl_msg msg;

    if (argz_is_set(pathz, "up")) {
        msg = (struct ctl_msg){
            .type = CTL_PATH_ADD,
        };
        str_cpy(msg.path.add.addr, sizeof(msg.path.add.addr) - 1, addr);
    } else if (argz_is_set(pathz, "down")) {
        msg = (struct ctl_msg){
            .type = CTL_PATH_DEL,
        };
        str_cpy(msg.path.del.addr, sizeof(msg.path.del.addr) - 1, addr);
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

    struct ctl_msg reply;

    if ((send(fd, &msg, sizeof(msg), 0) == -1) ||
        (recv(fd, &reply, sizeof(reply), 0) == -1)) {
        perror("send/recv");
        ctl_delete(fd);
        return 1;
    }

    switch (reply.type) {
    case CTL_REPLY:
        if (reply.reply) {
            errno = reply.reply;
            perror("error");
        }
        break;
    case CTL_UNKNOWN:
        printf("unknown command: %i\n", reply.unknown.type);
        break;
    default:
        gt_log("bad reply from server: %i\n", reply.type);
    }

    ctl_delete(fd);

    return 0;
}
