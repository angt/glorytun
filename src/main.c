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
    long port = 5000;

    char *bind_list = NULL;
    long bind_port = 5000;

    char *dev = NULL;
    char *keyfile = NULL;
    char *statefile = NULL;

    long mtu = 1450;

    gt.timeout = 5000;

    long time_tolerance = 0;

    int v4 = 1;
    int v6 = 0;

#ifdef __linux__
    v6 = 1;
#endif

    struct option opts[] = {
        { "host",           &host,           option_str    },
        { "port",           &port,           option_long   },
        { "bind",           &bind_list,      option_str    },
        { "bind-port",      &bind_port,      option_long   },
        { "dev",            &dev,            option_str    },
        { "mtu",            &mtu,            option_long   },
        { "keyfile",        &keyfile,        option_str    },
        { "statefile",      &statefile,      option_str    },
        { "timeout",        &gt.timeout,     option_long   },
        { "time-tolerance", &time_tolerance, option_long   },
        { "v4only",         NULL,            option_option },
        { "v6only",         NULL,            option_option },
        { "chacha20",       NULL,            option_option },
        { "version",        NULL,            option_option },
        { NULL },
    };

    if (option(opts, argc, argv))
        return 1;

    if (option_is_set(opts, "version")) {
        gt_print(PACKAGE_STRING"\n");
        return 0;
    }

    if (option_is_set(opts, "v4only")) {
        v4 = 1;
        v6 = 0;
    }

    if (option_is_set(opts, "v6only")) {
        v4 = 0;
        v6 = 1;
    }

    if (option_is_set(opts, "v4only") &&
        option_is_set(opts, "v6only")) {
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

    int icmp_fd = -1;

    if (v4) {
        icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (icmp_fd==-1)
            gt_log("couldn't create ICMP socket\n");
    }

    gt.state_fd = state_create(statefile);

    if (statefile && gt.state_fd==-1)
        return 1;

    char *tun_name = NULL;

    int tun_fd = tun_create(dev, &tun_name);

    if (tun_fd==-1) {
        gt_log("couldn't create tun device\n");
        return 1;
    }

    if (tun_set_mtu(tun_name, mtu)==-1) {
        perror("tun_set_mtu");
        return 1;
    }

    fd_set_nonblock(tun_fd);

    int chacha = option_is_set(opts, "chacha20");

    struct mud *mud = mud_create(bind_port, v4, v6, !chacha, mtu);

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

    fd_set_nonblock(mud_fd);

    state_send(gt.state_fd, "INITIALIZED", tun_name);

    fd_set rfds;
    FD_ZERO(&rfds);

    unsigned char buf[8*1024];

    while (!gt.quit) {
        FD_SET(tun_fd, &rfds);
        FD_SET(mud_fd, &rfds);

        if (icmp_fd!=-1)
            FD_SET(icmp_fd, &rfds);

        if _0_(select(mud_fd+1, &rfds, NULL, NULL, NULL)==-1) {
            if (errno==EINTR)
                continue;
            perror("select");
            return 1;
        }

        if (icmp_fd!=-1 && FD_ISSET(icmp_fd, &rfds)) {
            struct sockaddr_storage ss;
            socklen_t sl = sizeof(ss);
            ssize_t r = recvfrom(icmp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &sl);
            if (r>=8) {
                struct ip_common ic;
                if (!ip_get_common(&ic, buf, r) && ic.proto==1) {
                    unsigned char *data = &buf[ic.hdr_size];
                    if (data[0]==3) {
                        int new_mtu = (data[6]<<8)|data[7];
                        if (new_mtu) {
                            gt_log("received MTU from ICMP: %i\n", new_mtu);
                            mud_set_mtu(mud, new_mtu-50); // XXX
                        }
                    }
                }
            }
        }

        if (FD_ISSET(tun_fd, &rfds)) {
            size_t size = 0;

            while (sizeof(buf)-size>mtu) {
                const ssize_t r = tun_read(tun_fd, &buf[size], sizeof(buf)-size);

                if (r<=0)
                    break;

                struct ip_common ic;

                if (ip_get_common(&ic, &buf[size], r) || ic.size!=r)
                    break;

                size += r;
            }

            int p = 0;

            while (p<size) {
                int tc = 0;
                int q = p;

                while (q<size) {
                    struct ip_common ic;

                    if (ip_get_common(&ic, &buf[q], size-q) || ic.size>size-q) {
                        size = q;
                        break;
                    }

                    if (q+ic.size>p+mtu)
                        break;

                    q += ic.size;

                    if (tc<(ic.tc&0xFC))
                        tc = ic.tc&0xFC;
                }

                int r = mud_send(mud, &buf[p], q-p, tc);

                if (r==-1 && errno==EMSGSIZE) {
                    int new_mtu = mud_get_mtu(mud);

                    if (new_mtu!=mtu) {
                        mtu = new_mtu;

                        gt_log("MTU changed: %li\n", mtu);

                        if (tun_set_mtu(tun_name, mtu)==-1)
                            perror("tun_set_mtu");
                    }
                } else {
                    if (r==-1 && errno!=EAGAIN)
                        perror("mud_send");

                    p = q;
                }
            }
        }

        if (FD_ISSET(mud_fd, &rfds)) {
            while (1) {
                const int size = mud_recv(mud, buf, sizeof(buf));

                if (size<=0) {
                    if (size==-1 && errno!=EAGAIN)
                        perror("mud_recv");
                    break;
                }

                int p = 0;

                while (p<size) {
                    struct ip_common ic;

                    if (ip_get_common(&ic, &buf[p], size-p) || ic.size>size-p)
                        break;

                    tun_write(tun_fd, &buf[p], ic.size);

                    p += ic.size;
                }
            }
        }
    }

    return 0;
}
