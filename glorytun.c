#include "common.h"

#include <stdio.h>
#include <signal.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#define GT_BUFFER_SIZE (256*1024)

volatile sig_atomic_t running;

static int gt_open_sock (char *host, char *port, int listener)
{
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
        .ai_flags = AI_PASSIVE,
    };

    struct addrinfo *ai, *res = NULL;

    if (getaddrinfo(host, port, &hints, &res)) {
        printf("host not found\n");
        return -1;
    }

    int fd = -1;

    for (ai=res; ai; ai=ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (fd==-1)
            continue;

        int ret;

        if (listener) {
            const int val = 1;

            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))==-1)
                printf("setsockopt: %m\n");

            ret = bind(fd, ai->ai_addr, ai->ai_addrlen);

            if (!ret)
                ret = listen(fd, 1);
        } else {
            ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
        }

        if (!ret)
            break;

        if (errno)
            printf("socket: %m\n");

        close(fd);

        fd = -1;
    }

    freeaddrinfo(res);

    return fd;
}

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

static void gt_set_signal (void)
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

static int read_to_buffer (int fd, buffer_t *buffer)
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

static int write_from_buffer (int fd, buffer_t *buffer)
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

enum option_type {
    option_flag,
    option_string,
};

struct option {
    char *name;
    void *data;
    enum option_type type;
};

static void option (int argc, char **argv, int n, struct option *opt)
{
    for (int i=0; i<argc; i++) {
        for (int k=0; k<n; k++) {
            if (str_cmp(opt[k].name, argv[i]))
                continue;
            switch (opt[k].type) {
            case option_flag:
                {
                    const int val = 1;
                    byte_cpy(opt[k].data, &val, sizeof(val));
                    break;
                }
            case option_string:
                {
                    const char *val = argv[++i];
                    byte_cpy(opt[k].data, &val, sizeof(val));
                    break;
                }
            }
        }
    }
}

int main (int argc, char **argv)
{
    gt_set_signal();

    char *host = NULL;
    char *port = "5000";
    char *dev  = "glorytun";
    int listener = 0;

    struct option opts[] = {
        { "dev",      &dev,      option_string },
        { "host",     &host,     option_string },
        { "port",     &port,     option_string },
        { "listener", &listener, option_flag   },
    };

    option(argc, argv, COUNT(opts), opts);

    int tun_fd  = gt_open_tun(dev);
    int sock_fd = gt_open_sock(host, port, listener);

    if (tun_fd==-1 || sock_fd==-1)
        return 1;

    struct pollfd fds[] = {
        { .fd = tun_fd,  .events = POLLIN },
        { .fd = sock_fd, .events = POLLIN },
    };

    buffer_t input;
    buffer_setup(&input, NULL, GT_BUFFER_SIZE);

    while (running) {
        int ret = poll(fds, COUNT(fds), -1);

        if (ret==-1) {
            if (errno==EINTR)
                continue;
            printf("poll: %m\n");
            return 1;
        }

        if (ret==0)
            continue;

        if (fds[0].revents & POLLIN) {
            int read_ret = read_to_buffer(fds[0].fd, &input);
            printf("read %zu\n", buffer_read_size(&input));
            buffer_format(&input);
        }
    }

    free(input.data);

    return 0;
}
