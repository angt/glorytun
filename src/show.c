#include "common.h"
#include "ctl.h"

#include "../argz/argz.h"

#include <stdio.h>

static void
gt_show_bad_line(int term, char *name, uint64_t count,
                 struct sockaddr_storage *ss)
{
    if (!count)
        return;

    char addr[INET6_ADDRSTRLEN];
    gt_toaddr(addr, sizeof(addr), (struct sockaddr *)ss);

    printf(term ? "%s:\n"
                  "  count: %"PRIu64"\n"
                  "  last:  %s port %"PRIu16"\n"
                : "%s"
                  " %"PRIu64
                  " %s %"PRIu16
                  "\n",
           name, count, addr[0] ? addr : "-",
           gt_get_port((struct sockaddr *)ss));
}

static int
gt_show_bad(int fd)
{
    struct ctl_msg res, req = {.type = CTL_BAD};

    if (ctl_reply(fd, &res, &req))
        return -1;

    int term = isatty(1);

    gt_show_bad_line(term, "decrypt",
            res.bad.decrypt.count, &res.bad.decrypt.addr);
    gt_show_bad_line(term, "difftime",
            res.bad.difftime.count, &res.bad.difftime.addr);
    gt_show_bad_line(term, "keyx",
            res.bad.keyx.count, &res.bad.keyx.addr);

    return 0;
}

static int
gt_show_status(int fd)
{
    struct ctl_msg res, req = {.type = CTL_STATUS};

    if (ctl_reply(fd, &res, &req))
        return -1;

    char bindstr[INET6_ADDRSTRLEN];
    char peerstr[INET6_ADDRSTRLEN];

    gt_toaddr(bindstr, sizeof(bindstr),
              (struct sockaddr *)&res.status.bind);

    int server = gt_toaddr(peerstr, sizeof(peerstr),
                           (struct sockaddr *)&res.status.peer);

    int term = isatty(1);

    if (server) {
        printf(term ? "server %s:\n"
                      "  pid:    %li\n"
                      "  bind:   %s port %"PRIu16"\n"
                      "  mtu:    %zu\n"
                      "  cipher: %s\n"
                    : "server %s"
                      " %li"
                      " %s %"PRIu16
                      " %zu"
                      " %s"
                      "\n",
               res.status.tun_name,
               res.status.pid,
               bindstr[0] ? bindstr : "-",
               gt_get_port((struct sockaddr *)&res.status.bind),
               res.status.mtu,
               GT_CIPHER(res.status.chacha));
    } else {
        printf(term ? "client %s:\n"
                      "  pid:    %li\n"
                      "  bind:   %s port %"PRIu16"\n"
                      "  peer:   %s port %"PRIu16"\n"
                      "  mtu:    %zu\n"
                      "  cipher: %s\n"
                    : "client %s"
                      " %li"
                      " %s %"PRIu16
                      " %s %"PRIu16
                      " %zu"
                      " %s"
                      "\n",
               res.status.tun_name,
               res.status.pid,
               bindstr[0] ? bindstr : "-",
               gt_get_port((struct sockaddr *)&res.status.bind),
               peerstr[0] ? peerstr : "-",
               gt_get_port((struct sockaddr *)&res.status.peer),
               res.status.mtu,
               GT_CIPHER(res.status.chacha));
    }

    return 0;
}

int
gt_show(int argc, char **argv)
{
    const char *dev = NULL;

    struct argz showz[] = {
        {"dev", "NAME", &dev, argz_str},
        {"bad", NULL, NULL, argz_option},
        {NULL}};

    if (argz(showz, argc, argv))
        return 1;

    int fd = ctl_connect(dev);

    if (fd < 0) {
        switch (fd) {
        case -1:
            perror("show");
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

    int ret = argz_is_set(showz, "bad")
            ? gt_show_bad(fd)
            : gt_show_status(fd);

    if (ret == -1)
        perror("show");

    ctl_delete(fd);

    return !!ret;
}
