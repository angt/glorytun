#include "common.h"

#include "buffer.h"
#include "ip.h"
#include "str.h"
#include "option.h"
#include "tun.h"
#include "db.h"
#include "state.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netdb.h>

#include "mud.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static struct {
    volatile sig_atomic_t quit;
    volatile sig_atomic_t info;
    int timeout;
    int state_fd;
} gt;

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

static void gt_sa_handler (int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGQUIT:
    case SIGTERM:
        gt.quit = 1;
        break;
    case SIGUSR1:
        gt.info = 1;
        break;
    }
}

static void gt_set_signal (void)
{
    struct sigaction sa = {
        .sa_flags = 0,
    };

    sigemptyset(&sa.sa_mask);

    sa.sa_handler = gt_sa_handler;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
}

static ssize_t fd_read (int fd, void *data, size_t size)
{
    if ((fd==-1) || !size)
        return -1;

    ssize_t ret = read(fd, data, size);

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;

        if (errno)
            perror("read");

        return 0;
    }

    return ret;
}

static ssize_t fd_write (int fd, const void *data, size_t size)
{
    if ((fd==-1) || !size)
        return -1;

    ssize_t ret = write(fd, data, size);

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;

        if (errno==EPIPE || errno==ECONNRESET)
            return 0;

        if (errno)
            perror("write");

        return 0;
    }

    return ret;
}

static size_t fd_read_all (int fd, void *data, size_t size)
{
    size_t done = 0;

    while (done<size) {
        ssize_t ret = fd_read(fd, (uint8_t *)data+done, size-done);

        if (!ret)
            break;

        if (ret<0) {
            struct pollfd pollfd = {
                .fd = fd,
                .events = POLLIN,
            };

            if (!poll(&pollfd, 1, gt.timeout))
                break;

            continue;
        }

        done += ret;
    }

    return done;
}

static size_t fd_write_all (int fd, const void *data, size_t size)
{
    size_t done = 0;

    while (done<size) {
        ssize_t ret = fd_write(fd, (const uint8_t *)data+done, size-done);

        if (!ret)
            break;

        if (ret<0) {
            struct pollfd pollfd = {
                .fd = fd,
                .events = POLLOUT,
            };

            if (!poll(&pollfd, 1, gt.timeout))
                break;

            continue;
        }

        done += ret;
    }

    return done;
}

static int gt_setup_secretkey (struct mud *mud, char *keyfile)
{
    unsigned char key[32];

    if (str_empty(keyfile)) {
        char buf[2*sizeof(key)+1];
        size_t size = sizeof(key);

        if (mud_get_key(mud, key, &size))
            return -1;

        gt_tohex(buf, sizeof(buf), key, size);
        state_send(gt.state_fd, "SECRETKEY", buf);

        return 0;
    }

    int fd;

    do {
        fd = open(keyfile, O_RDONLY|O_CLOEXEC);
    } while (fd==-1 && errno==EINTR);

    if (fd==-1) {
        perror("open keyfile");
        return -1;
    }

    char buf[2*sizeof(key)];
    size_t r = fd_read_all(fd, buf, sizeof(buf));

    close(fd);

    if (r!=sizeof(buf)) {
        gt_log("unable to read secret key\n");
        return -1;
    }

    if (gt_fromhex(key, sizeof(key), buf, sizeof(buf))) {
        gt_log("secret key is not valid\n");
        return -1;
    }

    mud_set_key(mud, key, sizeof(key));

    return 0;
}

int main (int argc, char **argv)
{
    gt_set_signal();

    char *host = NULL;
    char *port = "5000";
    char *bind_list = NULL;
    char *bind_port = "5000";
    char *dev = NULL;
    char *keyfile = NULL;
    char *statefile = NULL;

    gt.timeout = 5000;

    long time_tolerance = 0;

    int v4 = 1;
    int v6 = 1;

    struct option opts[] = {
        { "host",           &host,           option_str    },
        { "port",           &port,           option_str    },
        { "bind",           &bind_list,      option_str    },
        { "bind-port",      &bind_port,      option_str    },
        { "dev",            &dev,            option_str    },
        { "keyfile",        &keyfile,        option_str    },
        { "multiqueue",     NULL,            option_option },
        { "statefile",      &statefile,      option_str    },
        { "timeout",        &gt.timeout,     option_long   },
        { "time-tolerance", &time_tolerance, option_long   },
        { "v4only",         NULL,            option_option },
        { "v6only",         NULL,            option_option },
        { "version",        NULL,            option_option },
        { NULL },
    };

    if (option(opts, argc, argv))
        return 1;

    if (option_is_set(opts, "version")) {
        gt_print(PACKAGE_STRING"\n");
        return 0;
    }

    if (option_is_set(opts, "v4only"))
        v6 = 0;

    if (option_is_set(opts, "v6only"))
        v4 = 0;

    if (!v4 && !v6) {
        gt_log("v4only and v6only are both set\n");
        return 1;
    }

    if (host && !option_is_set(opts, "keyfile")) {
        gt_log("keyfile option must be set\n");
        return 1;
    }

    if (gt.timeout<=0 || gt.timeout>INT_MAX) {
        gt_log("bad timeout\n");
        return 1;
    }

    gt.state_fd = state_create(statefile);

    if (statefile && gt.state_fd==-1)
        return 1;

    char *tun_name = NULL;

    int tun_fd = tun_create(dev, &tun_name, option_is_set(opts, "multiqueue"));

    if (tun_fd==-1) {
        gt_log("couldn't create tun device\n");
        return 1;
    }

    fd_set_nonblock(tun_fd);

    struct mud *mud = mud_create(bind_port, v4, v6);

    if (!mud) {
        gt_log("couldn't create mud\n");
        return 1;
    }

    if (gt_setup_secretkey(mud, keyfile))
        return 1;

    mud_set_send_timeout_msec(mud, gt.timeout);

    if (time_tolerance > 0)
        mud_set_time_tolerance_sec(mud, time_tolerance);

    if (host && port && bind_list) {
        char tmp[1024];
        char *name = &tmp[0];

        size_t size = str_cpy(tmp, bind_list, sizeof(tmp)-1);

        for (size_t i=0; i<size; i++) {
            if (tmp[i]!=',')
                continue;

            tmp[i] = 0;

            if (mud_peer(mud, name, host, port))
                return 1;

            name = &tmp[i+1];
        }

        if (name[0] && mud_peer(mud, name, host, port))
            return 1;
    }

    int mud_fd = mud_get_fd(mud);

    state_send(gt.state_fd, "INITIALIZED", tun_name);

    fd_set rfds;
    FD_ZERO(&rfds);

    int started = 0;
    unsigned char buf[2048];

    while (!gt.quit) {
        FD_SET(tun_fd, &rfds);

        if (mud_can_pull(mud)) {
            FD_SET(mud_fd, &rfds);
        } else {
            FD_CLR(mud_fd, &rfds);
        }

        struct timeval timeout = {
            .tv_usec = 100000,
        };

        if (mud_can_push(mud))
            timeout.tv_usec = 1000;

        if _0_(select(mud_fd+1, &rfds, NULL, NULL, &timeout)==-1) {
            if (errno==EINTR)
                continue;
            perror("select");
            return 1;
        }

        if (mud_is_up(mud)) {
            if (!started) {
                state_send(gt.state_fd, "STARTED", tun_name);
                started = 1;
            }
        } else {
            if (started) {
                state_send(gt.state_fd, "STOPPED", tun_name);
                started = 0;
            }
        }

        if (FD_ISSET(tun_fd, &rfds)) {
            while (1) {
                const ssize_t r = tun_read(tun_fd, buf, sizeof(buf));

                if (r<=0) {
                    gt.quit |= !r;
                    break;
                }

                struct ip_common ic;

                if (!ip_get_common(&ic, buf, sizeof(buf)) && ic.size==r)
                    mud_send(mud, buf, r);
            }
        }

        mud_push(mud);

        if (FD_ISSET(mud_fd, &rfds))
            mud_pull(mud);

        while (1) {
            const int size = mud_recv(mud, buf, sizeof(buf));

            if (size<=0)
                break;

            const ssize_t r = tun_write(tun_fd, buf, size);

            if (r<=0) {
                gt.quit |= !r;
                break;
            }
        }
    }

    return 0;
}
