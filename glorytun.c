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

static void gt_sa_stop (int sig)
{
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
    sigaction(SIGPIPE, &sa, NULL);
}

static inline int buffer_read_fd (buffer_t *buffer, int fd)
{
    buffer_shift(buffer);

    size_t size = buffer_write_size(buffer);

    if (!size)
        return -1;

    ssize_t ret = read(fd, buffer->write, size);

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;
        if (errno)
            printf("read: %m\n");
        return 0;
    }

    buffer->write += ret;

    return 1;
}

static inline int buffer_write_fd (buffer_t *buffer, int fd)
{
    size_t size = buffer_read_size(buffer);

    if (!size)
        return -1;

    ssize_t ret = write(fd, buffer->read, size);

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;
        if (errno)
            printf("read: %m\n");
        return 0;
    }

    buffer->read += ret;

    buffer_shift(buffer);

    return 1;
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

    buffer_t input;
    buffer_setup(&input, NULL, 256*1024);

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
            int read_ret = buffer_read_fd(&input, fds[0].fd);
            printf("read %zu\n", buffer_read_size(&input));
            buffer_format(&input);
        }
    }

    free(input.data);

    return 0;
}
