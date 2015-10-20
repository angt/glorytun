#include "common.h"

#include <stdio.h>
#include <signal.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#define GT_NAME "glorytun"

volatile sig_atomic_t running;

static int gt_open_tun (char *name)
{
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd<0) {
        printf("open /dev/net/tun: %m\n");
        return -1;
    }

    struct ifreq ifr = {
        .ifr_flags = IFF_TUN|IFF_NO_PI,
    };

    str_cpy(ifr.ifr_name, name, IFNAMSIZ-1);

    int ret = ioctl(fd, TUNSETIFF, &ifr);

    if (ret<0) {
        printf("ioctl TUNSETIFF: %m\n");
        return -1;
    }

    printf("tun name: %s\n", ifr.ifr_name);

    return fd;
}

static void gt_sa_stop (int sig) {
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        running = 0;
    }
}

static int gt_set_signal (void)
{
    struct sigaction sa = {0};

    running = 1;

    sa.sa_handler = gt_sa_stop;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGHUP,  &sa, NULL);
}

int main (int argc, char **argv)
{
    gt_set_signal();

    int tun_fd = gt_open_tun(GT_NAME);

    if (tun_fd==-1)
        return 1;

    struct pollfd fds[] = {
        { .fd = tun_fd, .events = POLLIN },
    };

    while (running) {
        int ret = poll(fds, COUNT(fds), 0);

        if (ret==-1) {
            if (errno==EINTR)
                continue;
            printf("poll: %m\n");
            return 1;
        }

        if (ret==0)
            continue;

        if (fds[0].revents & POLLIN) {
            printf("POLLIN!\n");
        }
    }

    return 0;
}
