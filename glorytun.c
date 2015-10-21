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

static int read_to_buffer (int fd, buffer_t *buffer, size_t size)
{
    if (!size || buffer_write_size(buffer)<size)
        return -1;

    ssize_t ret = read(fd, buffer->write, size);

    if (!ret)
        return 0;

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;
        if (errno)
            printf("read: %m\n");
        return 0;
    }

    buffer->write += ret;

    return ret;
}

static int write_from_buffer (int fd, buffer_t *buffer, size_t size)
{
    if (!size || buffer_read_size(buffer)<size)
        return -1;

    ssize_t ret = write(fd, buffer->read, size);

    if (!ret)
        return 0;

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;
        if (errno)
            printf("write: %m\n");
        return 0;
    }

    buffer->read += ret;

    return ret;
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

static int option (int argc, char **argv, int n, struct option *opt)
{
    for (int i=1; i<argc; i++) {
        int found = 0;
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
            found = 1;
            break;
        }
        if (!found) {
            printf("option `%s' is unknown\n", argv[i]);
            return 1;
        }
    }

    return 0;
}

struct netio {
    int fd;
    buffer_t recv;
    buffer_t send; // TODO
};

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

    if (option(argc, argv, COUNT(opts), opts))
        return 1;

    struct netio tun  = { .fd = -1 };
    struct netio sock = { .fd = -1 };

    int fd = gt_open_sock(host, port, listener);

    if (fd==-1)
        return 1;

    tun.fd = gt_open_tun(dev);

    if (tun.fd==-1)
        return 1;

    while (running) {

        if (listener) {
            printf("waiting for a client...\n");

            struct sockaddr_storage addr_storage;
            struct sockaddr *addr = (struct sockaddr *)&addr_storage;
            socklen_t addr_size = sizeof(addr_storage);
            sock.fd = accept(fd, addr, &addr_size);

            if (sock.fd==-1) {
                printf("accept: %m\n");
                return 1;
            }

            // setup socket
        } else {
            // reconnect
            sock.fd = fd;
        }

        printf("running...\n");

        buffer_setup(&tun.recv, NULL, GT_BUFFER_SIZE);
        buffer_setup(&sock.recv, NULL, GT_BUFFER_SIZE);

        while (running) {

            struct pollfd fds[] = {
                { .fd = tun.fd,  .events = POLLIN },
                { .fd = sock.fd, .events = POLLIN },
            };

            int ret = poll(fds, COUNT(fds), -1);

            if (ret==-1) {
                if (errno==EINTR)
                    continue;
                printf("poll: %m\n");
                return 1;
            }

            if (ret==0)
                continue;

            buffer_shift(&tun.recv);

            if (fds[0].revents & POLLIN) {
                if (buffer_write_size(&tun.recv)) {
                    uint8_t *tmp = tun.recv.write;
                    int r = read_to_buffer(fds[0].fd, &tun.recv, buffer_write_size(&tun.recv));
                    if (!r)
                        return 2;
                    if (r>0 && r!=((tmp[2]<<8)|tmp[3]))
                        tun.recv.write = tmp;
                }
            }

            if (fds[1].revents & POLLOUT)
                fds[1].events = POLLIN;

            if (buffer_read_size(&tun.recv)) {
                int r = write_from_buffer(fds[1].fd, &tun.recv, buffer_read_size(&tun.recv));
                if (!r)
                    goto restart;
                if (r==-1)
                    fds[1].events = POLLIN|POLLOUT;
            }

            buffer_shift(&sock.recv);

            if (fds[1].revents & POLLIN) {
                int r = read_to_buffer(fds[1].fd, &sock.recv, buffer_write_size(&sock.recv));
                if (!r)
                    goto restart;
            }

            if (fds[0].revents & POLLOUT)
                fds[0].events = POLLIN;

            if (buffer_read_size(&sock.recv)>=20) {
                if ((sock.recv.read[0]>>4)!=4)
                    return 4;
                size_t ps = (sock.recv.read[2]<<8)|sock.recv.read[3];
                if (buffer_read_size(&sock.recv)>=ps) {
                    int r = write_from_buffer(fds[0].fd, &sock.recv, ps);
                    if (!r)
                        return 2;
                    if (r==-1)
                        fds[0].events = POLLIN|POLLOUT;
                }
            }
        }

    restart:
        free(tun.recv.data);
        free(sock.recv.data);
    }

    return 0;
}
