#include "common-static.h"

#include <stdio.h>
#include <signal.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef __linux__
# include <linux/if.h>
# include <linux/if_tun.h>
#endif

#define GT_BUFFER_SIZE (256*1024)

volatile sig_atomic_t running;

static void fd_set_nonblock (int fd)
{
    int ret;

    do {
        ret = fcntl(fd, F_GETFL, 0);
    } while (ret==-1 && errno==EINTR);

    int flags = (ret==-1)?0:ret;

    do {
        ret = fcntl(fd, F_SETFL, flags|O_NONBLOCK);
    } while (ret==-1 && errno==EINTR);

    if (ret==-1)
        perror("fcntl O_NONBLOCK");
}

static void sk_set_nodelay (int fd)
{
    int val = 1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY , &val, sizeof(val))==-1)
        perror("setsockopt TCP_NODELAY");
}

static void sk_set_reuseaddr (int fd)
{
    int val = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))==-1)
        perror("setsockopt SO_REUSEADDR");
}

static void sk_set_congestion (int fd, const char *name)
{
    size_t len = str_len(name);

    if (!len)
        return;

#ifdef TCP_CONGESTION
    if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name, len+1)==-1)
        perror("setsockopt TCP_CONGESTION");
#else
    (void) fd;
#endif
}

static int sk_listen (int fd, struct addrinfo *ai)
{
    sk_set_reuseaddr(fd);

    int ret = bind(fd, ai->ai_addr, ai->ai_addrlen);

    if (ret==-1) {
        perror("bind");
        return -1;
    }

    ret = listen(fd, 1);

    if (ret==-1) {
        perror("listen");
        return -1;
    }

    return 0;
}

static int sk_connect (int fd, struct addrinfo *ai)
{
    return connect(fd, ai->ai_addr, ai->ai_addrlen);
}

static int sk_create (struct addrinfo *res, int(*func)(int, struct addrinfo *))
{
    for (struct addrinfo *ai=res; ai; ai=ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (fd==-1)
            continue;

        if (func(fd, ai)!=-1)
            return fd;

        close(fd);
    }

    return -1;
}

#ifdef __linux__
static int tun_create (char *name)
{
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd<0) {
        perror("open /dev/net/tun");
        return -1;
    }

    struct ifreq ifr = {
        .ifr_flags = IFF_TUN|IFF_NO_PI,
    };

    str_cpy(ifr.ifr_name, name, IFNAMSIZ-1);

    int ret = ioctl(fd, TUNSETIFF, &ifr);

    if (ret<0) {
        perror("ioctl TUNSETIFF");
        return -1;
    }

    printf("tun name: %s\n", ifr.ifr_name);

    return fd;
}
#else
static int tun_create (char *name)
{
    (void) name;

    for (unsigned dev_id = 0U; dev_id < 32U; dev_id++) {
        char dev_path[11U];
        snprintf(dev_path, sizeof(dev_path), "/dev/tun%u", dev_id);

        int fd = open(dev_path, O_RDWR);

        if (fd!=-1)
            return fd;
    }

    return -1;
}
#endif

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
    struct sigaction sa;

    byte_set(&sa, 0, sizeof(sa));
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
            perror("read");
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
            perror("write");
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
    char *congestion = NULL;

    struct option opts[] = {
        { "dev",        &dev,        option_string },
        { "host",       &host,       option_string },
        { "port",       &port,       option_string },
        { "listener",   &listener,   option_flag   },
        { "congestion", &congestion, option_string },
    };

    if (option(argc, argv, COUNT(opts), opts))
        return 1;

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };

    if (listener)
        hints.ai_flags = AI_PASSIVE;

    struct addrinfo *ai = NULL;

    if (getaddrinfo(host, port, &hints, &ai)) {
        printf("host not found\n");
        return 1;
    }

    int fd = listener?sk_create(ai, sk_listen):-1;
    
    struct netio tun  = { .fd = -1 };
    struct netio sock = { .fd = -1 };

    tun.fd = tun_create(dev);

    if (tun.fd==-1)
        return 1;

    fd_set_nonblock(tun.fd);

    buffer_setup(&tun.recv, NULL, GT_BUFFER_SIZE);
    buffer_setup(&sock.recv, NULL, GT_BUFFER_SIZE);

    while (running) {

        if (listener) {
            printf("waiting for a client...\n");

            struct sockaddr_storage addr_storage;
            struct sockaddr *addr = (struct sockaddr *)&addr_storage;
            socklen_t addr_size = sizeof(addr_storage);
            sock.fd = accept(fd, addr, &addr_size);

            if (sock.fd==-1) {
                perror("accept");
                return 1;
            }
        } else {
            sock.fd = sk_create(ai, sk_connect);

            if (sock.fd==-1)
                continue;
        }

        fd_set_nonblock(sock.fd);
        sk_set_nodelay(sock.fd);
        sk_set_congestion(sock.fd, congestion);

        printf("running...\n");

        buffer_format(&tun.recv);
        buffer_format(&sock.recv);

        while (running) {

            struct pollfd fds[] = {
                { .fd = tun.fd,  .events = POLLIN },
                { .fd = sock.fd, .events = POLLIN },
            };

            int ret = poll(fds, COUNT(fds), -1);

            if (ret==-1) {
                if (errno==EINTR)
                    continue;
                perror("poll");
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
        close(sock.fd);
        sock.fd = -1;
    }

    if (ai)
        freeaddrinfo(ai);

    free(tun.recv.data);
    free(sock.recv.data);

    return 0;
}
