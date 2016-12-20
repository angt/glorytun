#include "common.h"

#include "db.h"
#include "ip.h"
#include "option.h"
#include "str.h"
#include "tun.h"

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
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
    int timeout;
} gt;

static void
fd_set_nonblock(int fd)
{
    int ret;

    do {
        ret = fcntl(fd, F_GETFL, 0);
    } while (ret == -1 && errno == EINTR);

    int flags = (ret == -1) ? 0 : ret;

    do {
        ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1)
        perror("fcntl O_NONBLOCK");
}

static void
gt_quit_handler(int sig)
{
    gt.quit = 1;
}

static void
gt_set_signal(void)
{
    struct sigaction sa = {
        .sa_flags = 0,
    };

    sigemptyset(&sa.sa_mask);

    sa.sa_handler = gt_quit_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

static void
gt_print_secretkey(struct mud *mud)
{
    unsigned char key[32];
    size_t size = sizeof(key);

    if (mud_get_key(mud, key, &size))
        return;

    char buf[2 * sizeof(key) + 1];

    gt_tohex(buf, sizeof(buf), key, size);
    gt_print("secret key: %s\n", buf);
}

static int
gt_setup_secretkey(struct mud *mud, char *keyfile)
{
    int fd;

    do {
        fd = open(keyfile, O_RDONLY | O_CLOEXEC);
    } while (fd == -1 && errno == EINTR);

    if (fd == -1) {
        perror("open keyfile");
        return -1;
    }

    unsigned char key[32];
    char buf[2 * sizeof(key)];
    size_t size = 0;

    while (size < sizeof(buf)) {
        ssize_t r = read(fd, &buf[size], sizeof(buf) - size);

        if (r <= (ssize_t)0) {
            if (r && (errno == EAGAIN || errno == EINTR))
                continue;
            break;
        }

        size += r;
    }

    close(fd);

    if (size != sizeof(buf)) {
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

int
main(int argc, char **argv)
{
    gt_set_signal();

    char *host = NULL;
    long port = 5000;

    char *bind_list = NULL;
    char *bind_backup = NULL;
    long bind_port = 5000;

    char *dev = NULL;
    char *keyfile = NULL;

    long mtu = 1450;

    gt.timeout = 5000;

    long time_tolerance = 0;

    int v4 = 1;
    int v6 = 0;

#ifdef __linux__
    v6 = 1;
#endif

    struct option opts[] = {
        // clang-format off
        { "host",           &host,           option_str    },
        { "port",           &port,           option_long   },
        { "bind",           &bind_list,      option_str    },
        { "bind-backup",    &bind_backup,    option_str    },
        { "bind-port",      &bind_port,      option_long   },
        { "dev",            &dev,            option_str    },
        { "mtu",            &mtu,            option_long   },
        { "mtu-auto",       NULL,            option_option },
        { "keyfile",        &keyfile,        option_str    },
        { "timeout",        &gt.timeout,     option_long   },
        { "time-tolerance", &time_tolerance, option_long   },
        { "v4only",         NULL,            option_option },
        { "v6only",         NULL,            option_option },
        { "chacha20",       NULL,            option_option },
        { "version",        NULL,            option_option },
        {  NULL                                            },
        // clang-format on
    };

    if (option(opts, argc, argv))
        return 1;

    if (option_is_set(opts, "version")) {
        gt_print(PACKAGE_STRING "\n");
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

    if (gt.timeout <= 0 || gt.timeout > INT_MAX) {
        gt_log("bad timeout\n");
        return 1;
    }

    int icmp_fd = -1;

    if (v4 && option_is_set(opts, "mtu-auto")) {
        icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (icmp_fd == -1)
            gt_log("couldn't create ICMP socket\n");
    }

    char *tun_name = NULL;

    int tun_fd = tun_create(dev, &tun_name);

    if (tun_fd == -1) {
        gt_log("couldn't create tun device\n");
        return 1;
    }

    if (tun_set_mtu(tun_name, mtu) == -1) {
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

    if (str_empty(keyfile)) {
        gt_print_secretkey(mud);
    } else {
        if (gt_setup_secretkey(mud, keyfile))
            return 1;
    }

    mud_set_send_timeout_msec(mud, gt.timeout);

    if (time_tolerance > 0)
        mud_set_time_tolerance_sec(mud, time_tolerance);

    if (host && port) {
        if (bind_backup) {
            if (mud_peer(mud, bind_backup, host, port, 1)) {
                perror("mud_peer (backup)");
                return 1;
            }
        }

        if (bind_list) {
            char tmp[1024];
            char *name = &tmp[0];

            str_cpy(tmp, bind_list, sizeof(tmp) - 1);

            while (*name) {
                char *p = name;

                while (*p && *p != ',')
                    p++;

                if (*p)
                    *p++ = 0;

                if (mud_peer(mud, name, host, port, 0)) {
                    perror("mud_peer");
                    return 1;
                }

                name = p;
            }
        }
    }

    int mud_fd = mud_get_fd(mud);

    fd_set_nonblock(mud_fd);

    gt_log("running...\n");

    fd_set rfds;
    FD_ZERO(&rfds);

    unsigned char buf[8 * 1024];

    while (!gt.quit) {
        FD_SET(tun_fd, &rfds);
        FD_SET(mud_fd, &rfds);

        if (icmp_fd != -1)
            FD_SET(icmp_fd, &rfds);

        if (select(mud_fd + 1, &rfds, NULL, NULL, NULL) == -1) {
            if (errno == EINTR)
                continue;
            perror("select");
            return 1;
        }

        if (icmp_fd != -1 && FD_ISSET(icmp_fd, &rfds)) {
            struct sockaddr_storage ss;
            socklen_t sl = sizeof(ss);
            ssize_t r = recvfrom(icmp_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&ss, &sl);
            if (r >= 8) {
                struct ip_common ic;
                if (!ip_get_common(&ic, buf, r) && ic.proto == 1) {
                    unsigned char *data = &buf[ic.hdr_size];
                    if (data[0] == 3) {
                        int new_mtu = (data[6] << 8) | data[7];
                        if (new_mtu) {
                            gt_log("received MTU from ICMP: %i\n", new_mtu);
                            mud_set_mtu(mud, new_mtu - 50); // XXX
                        }
                    }
                }
            }
        }

        if (FD_ISSET(tun_fd, &rfds)) {
            size_t size = 0;

            while (sizeof(buf) - size > mtu) {
                const ssize_t r = tun_read(tun_fd, &buf[size],
                                           sizeof(buf) - size);
                if (r <= 0)
                    break;

                struct ip_common ic;

                if (ip_get_common(&ic, &buf[size], r) || ic.size != r)
                    break;

                size += r;
            }

            int p = 0;

            while (p < size) {
                int tc = 0;
                int q = p;

                while (q < size) {
                    struct ip_common ic;

                    if ((ip_get_common(&ic, &buf[q], size - q)) ||
                        (ic.size > size - q)) {
                        size = q;
                        break;
                    }

                    if (q + ic.size > p + mtu)
                        break;

                    q += ic.size;

                    if (tc < (ic.tc & 0xFC))
                        tc = ic.tc & 0xFC;
                }

                int r = mud_send(mud, &buf[p], q - p, tc);

                if (r == -1 && errno == EMSGSIZE) {
                    int new_mtu = mud_get_mtu(mud);

                    if (new_mtu != mtu) {
                        mtu = new_mtu;

                        gt_log("MTU changed: %li\n", mtu);

                        if (tun_set_mtu(tun_name, mtu) == -1)
                            perror("tun_set_mtu");
                    }
                } else {
                    if (r == -1 && errno != EAGAIN)
                        perror("mud_send");

                    p = q;
                }
            }
        }

        if (FD_ISSET(mud_fd, &rfds)) {
            while (1) {
                const int size = mud_recv(mud, buf, sizeof(buf));

                if (size <= 0) {
                    if (size == -1 && errno != EAGAIN)
                        perror("mud_recv");
                    break;
                }

                int p = 0;

                while (p < size) {
                    struct ip_common ic;

                    if ((ip_get_common(&ic, &buf[p], size - p)) ||
                        (ic.size > size - p))
                        break;

                    tun_write(tun_fd, &buf[p], ic.size);

                    p += ic.size;
                }
            }
        }
    }

    return 0;
}
