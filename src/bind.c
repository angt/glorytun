#include "common.h"
#include "ctl.h"
#include "iface.h"
#include "ip.h"
#include "str.h"
#include "tun.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>

#include "../argz/argz.h"
#include "../mud/mud.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifdef __linux__
#define GT_IPV6 1
#else
#define GT_IPV6 0
#endif

#define GT_MTU(X) ((X)-28)

static void
fd_set_nonblock(int fd)
{
    int ret;

    if (fd == -1)
        return;

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

static int
gt_setup_secretkey(struct mud *mud, const char *keyfile)
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

static void
gt_setup_mtu(struct mud *mud, const char *tun_name, size_t *old_mtu)
{
    int mtu = mud_get_mtu(mud);

    if ((size_t)mtu == *old_mtu)
        return;

    gt_log("setup MTU to %i on interface %s\n", mtu, tun_name);

    if (iface_set_mtu(tun_name, mtu) == -1)
        perror("tun_set_mtu");

    *old_mtu = (size_t)mtu;
}

int
gt_bind(int argc, char **argv)
{
    unsigned short bind_port = 5000;
    unsigned short port = bind_port;
    const char *host = NULL;
    const char *dev = NULL;
    const char *keyfile = NULL;
    unsigned long timeout = 5000;
    unsigned long timetolerance = 0;
    size_t bufsize = 64 * 1024 * 1024;
    size_t mtu = 1500;

    struct argz mtuz[] = {
        {"auto", NULL, NULL, argz_option},
        {NULL, "BYTES", &mtu, argz_bytes},
        {}};

    struct argz toz[] = {
        {NULL, "IPADDR", &host, argz_str},
        {NULL, "PORT", &port, argz_ushort},
        {}};

    struct argz bindz[] = {
        {"port", "PORT", &bind_port, argz_ushort},
        {"to", NULL, &toz, argz_option},
        {"dev", "NAME", &dev, argz_str},
        {"v4only|v6only", NULL, NULL, argz_option},
        {"mtu", NULL, &mtuz, argz_option},
        {"keyfile", "FILE", &keyfile, argz_str},
        {"chacha", NULL, NULL, argz_option},
        {"timeout", "SECONDS", &timeout, argz_time},
        {"timetolerance", "SECONDS", &timetolerance, argz_time},
        {"persist", NULL, NULL, argz_option},
        {"bufsize", "BYTES", &bufsize, argz_bytes},
        {}};

    if (argz(bindz, argc, argv))
        return 1;

    unsigned char *buf = malloc(bufsize);

    if (!buf) {
        perror("malloc");
        return 1;
    }

    int ipv4 = 1;
    int ipv6 = GT_IPV6;

    if (argz_is_set(bindz, "v4only")) {
        ipv4 = 1;
        ipv6 = 0;
    }

    if (argz_is_set(bindz, "v6only")) {
        ipv4 = 0;
        ipv6 = 1;
    }

    int mtu_auto = argz_is_set(mtuz, "auto");
    int chacha = argz_is_set(bindz, "chacha");
    int persist = argz_is_set(bindz, "persist");

    int icmp_fd = -1;

    if (ipv4 && mtu_auto && host) {
        icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

        if (icmp_fd == -1)
            gt_log("couldn't create ICMP socket\n");
    }

    struct mud *mud = mud_create(bind_port, ipv4, ipv6);

    if (!mud) {
        gt_log("couldn't create mud\n");
        return 1;
    }

    if (str_empty(keyfile)) {
        if (mud_set_key(mud, NULL, 0)) {
            gt_log("couldn't generate a new key\n");
            return 1;
        }
    } else {
        if (gt_setup_secretkey(mud, keyfile))
            return 1;
    }

    if (!chacha && mud_set_aes(mud)) {
        gt_log("AES is not available\n");
        chacha = 1;
    }

    if (timeout && mud_set_send_timeout(mud, timeout)) {
        perror("timeout");
        return 1;
    }

    if (timetolerance && mud_set_time_tolerance(mud, timetolerance)) {
        perror("timetolerance");
        return 1;
    }

    mud_set_mtu(mud, GT_MTU(mtu));

    char tun_name[64];
    int tun_fd = tun_create(tun_name, sizeof(tun_name) - 1, dev);

    if (tun_fd == -1) {
        gt_log("couldn't create tun device\n");
        return 1;
    }

    if (tun_set_persist(tun_fd, persist) == -1)
        perror("tun_set_persist");

    if (host && port) {
        if (mud_peer(mud, host, port)) {
            perror("mud_peer");
            return 1;
        }
    }

    gt_setup_mtu(mud, tun_name, &mtu);

    int ctl_fd = ctl_create("/run/" PACKAGE_NAME, tun_name);

    if (ctl_fd == -1) {
        perror("ctl_create");
        return 1;
    }

    int mud_fd = mud_get_fd(mud);

    fd_set_nonblock(tun_fd);
    fd_set_nonblock(mud_fd);
    fd_set_nonblock(icmp_fd);
    fd_set_nonblock(ctl_fd);

    gt_log("running...\n");

    fd_set rfds;
    FD_ZERO(&rfds);

    int last_fd = 1 + MAX(tun_fd, MAX(mud_fd, MAX(ctl_fd, icmp_fd)));

    while (!gt_quit) {
        FD_SET(tun_fd, &rfds);
        FD_SET(mud_fd, &rfds);
        FD_SET(ctl_fd, &rfds);

        if (icmp_fd != -1)
            FD_SET(icmp_fd, &rfds);

        if (select(last_fd, &rfds, NULL, NULL, NULL) == -1) {
            if (errno != EBADF)
                continue;
            perror("select");
            return 1;
        }

        if (icmp_fd != -1 && FD_ISSET(icmp_fd, &rfds)) {
            struct ip_common ic;
            struct sockaddr_storage ss;
            socklen_t sl = sizeof(ss);

            ssize_t r = recvfrom(icmp_fd, buf, bufsize, 0,
                                 (struct sockaddr *)&ss, &sl);

            if (!ip_get_common(&ic, buf, r)) {
                int mtu = ip_get_mtu(&ic, buf, r);
                if (mtu > 0) {
                    gt_log("received MTU from ICMP: %i\n", mtu);
                    mud_set_mtu(mud, GT_MTU(mtu));
                }
            }
        }

        if (FD_ISSET(ctl_fd, &rfds)) {
            struct ctl_msg msg, reply = {.type = CTL_REPLY};
            struct sockaddr_storage ss;
            socklen_t sl = sizeof(ss);

            ssize_t r = recvfrom(ctl_fd, &msg, sizeof(msg), 0,
                                 (struct sockaddr *)&ss, &sl);

            if (r == (ssize_t)sizeof(msg)) {
                switch (msg.type) {
                case CTL_PATH_ADD:
                    gt_log("[ctl path add] addr=%s\n",
                           &msg.path.add.addr[0]);
                    if (mud_add_path(mud, &msg.path.add.addr[0])) {
                        reply.reply = errno;
                        perror("mud_add_path");
                    }
                    break;
                case CTL_PATH_DEL:
                    gt_log("[ctl path del] addr=%s\n",
                           &msg.path.del.addr[0]);
                    if (mud_del_path(mud, &msg.path.del.addr[0])) {
                        reply.reply = errno;
                        perror("mud_del_path");
                    }
                    break;
                case CTL_STATUS:
                    gt_log("[ctl status]\n");
                    reply = (struct ctl_msg){
                        .type = CTL_STATUS_REPLY,
                        .status = {
                            .mtu = mtu,
                            .mtu_auto = (icmp_fd != -1),
                            .chacha = chacha,
                            .port = port,
                            .bind_port = bind_port,
                            .ipv4 = ipv4,
                            .ipv6 = ipv6,
                        },
                    };
                    str_cpy(reply.status.addr, sizeof(reply.status.addr) - 1, host);
                    break;
                default:
                    reply = (struct ctl_msg){
                        .type = CTL_UNKNOWN,
                        .unknown = {
                            .type = msg.type,
                        },
                    };
                    break;
                }
                if (sendto(ctl_fd, &reply, sizeof(reply), 0,
                           (const struct sockaddr *)&ss, sl) == -1)
                    perror("sendto(ctl)");
            } else if (r == -1 && errno != EAGAIN) {
                perror("recvfrom(ctl)");
            }
        }

        if (FD_ISSET(tun_fd, &rfds)) {
            size_t size = 0;

            while (bufsize - size >= mtu) {
                const int r = tun_read(tun_fd, &buf[size], bufsize - size);

                if (r <= 0 || r > mtu)
                    break;

                struct ip_common ic;

                if (ip_get_common(&ic, &buf[size], r) || ic.size != r)
                    break;

                size += r;
            }

            size_t p = 0;

            while (p < size) {
                size_t q = p;
                int tc = 0;

                while (q < size) {
                    struct ip_common ic;

                    if ((ip_get_common(&ic, &buf[q], size - q)) ||
                        (ic.size > size - q))
                        break;

                    if (q + ic.size > p + mtu)
                        break;

                    q += ic.size;

                    if (tc < (ic.tc & 0xFC))
                        tc = ic.tc & 0xFC;
                }

                if (p >= q)
                    break;

                int r = mud_send(mud, &buf[p], q - p, tc);

                if (r == -1 && errno == EMSGSIZE) {
                    gt_setup_mtu(mud, tun_name, &mtu);
                } else {
                    if (r == -1 && errno != EAGAIN)
                        perror("mud_send");
                }

                p = q;
            }
        }

        if (FD_ISSET(mud_fd, &rfds)) {
            size_t size = 0;

            while (bufsize - size >= mtu) {
                const int r = mud_recv(mud, &buf[size], bufsize - size);

                if (r <= 0) {
                    if (r == -1 && errno != EAGAIN)
                        perror("mud_recv");
                    break;
                }

                size += r;
            }

            size_t p = 0;

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

    if (gt_reload && tun_fd >= 0) {
        if (tun_set_persist(tun_fd, 1) == -1)
            perror("tun_set_persist");
    }

    ctl_delete(ctl_fd);

    return 0;
}
