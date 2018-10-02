#include "common.h"
#include "ctl.h"
#include "iface.h"
#include "ip.h"
#include "str.h"
#include "tun.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/select.h>

#include "../argz/argz.h"
#include "../mud/mud.h"

#include <sodium.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

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

static size_t
gt_setup_mtu(struct mud *mud, const char *tun_name)
{
    static size_t oldmtu = 0;
    size_t mtu = mud_get_mtu(mud);

    if (mtu == oldmtu)
        return mtu;

    if (iface_set_mtu(tun_name, mtu) == -1)
        perror("tun_set_mtu");

    oldmtu = mtu;

    return mtu;
}

int
gt_bind(int argc, char **argv)
{
    struct sockaddr_storage bind_addr = { .ss_family = AF_INET };
    struct sockaddr_storage peer_addr = { 0 };
    unsigned short bind_port = 5000;
    unsigned short peer_port = bind_port;
    const char *dev = NULL;
    const char *keyfile = NULL;
    unsigned long sync = 0;

    struct argz toz[] = {
        {NULL, "IPADDR", &peer_addr, argz_addr},
        {NULL, "PORT", &peer_port, argz_ushort},
        {NULL}};

    struct argz bindz[] = {
        {NULL, "IPADDR", &bind_addr, argz_addr},
        {NULL, "PORT", &bind_port, argz_ushort},
        {"to", NULL, &toz, argz_option},
        {"dev", "NAME", &dev, argz_str},
        {"keyfile", "FILE", &keyfile, argz_str},
        {"chacha", NULL, NULL, argz_option},
        {"persist", NULL, NULL, argz_option},
        {"sync", "SECONDS", &sync, argz_time},
        {NULL}};

    if (argz(bindz, argc, argv))
        return 1;

    if (str_empty(keyfile)) {
        gt_log("a keyfile is needed!\n");
        return 1;
    }

    gt_set_port((struct sockaddr *)&bind_addr, bind_port);
    gt_set_port((struct sockaddr *)&peer_addr, peer_port);

    const size_t bufsize = 4096U;
    unsigned char *buf = malloc(bufsize);

    if (!buf) {
        perror("malloc");
        return 1;
    }

    int chacha = argz_is_set(bindz, "chacha");
    int persist = argz_is_set(bindz, "persist");

    if (sodium_init() == -1) {
        gt_log("couldn't init sodium\n");
        return 1;
    }

    unsigned char hashkey[crypto_shorthash_KEYBYTES];
    randombytes_buf(hashkey, sizeof(hashkey));

    struct mud *mud = mud_create((struct sockaddr *)&bind_addr);

    if (!mud) {
        gt_log("couldn't create mud\n");
        return 1;
    }

    if (gt_setup_secretkey(mud, keyfile))
        return 1;

    if (!chacha && mud_set_aes(mud)) {
        gt_log("AES is not available, enjoy ChaCha20!\n");
        chacha = 1;
    }

    char tun_name[64];
    const int tun_fd = tun_create(tun_name, sizeof(tun_name) - 1, dev);

    if (tun_fd == -1) {
        gt_log("couldn't create tun device\n");
        return 1;
    }

    size_t mtu = gt_setup_mtu(mud, tun_name);

    if (tun_set_persist(tun_fd, persist) == -1)
        perror("tun_set_persist");

    if (peer_addr.ss_family) {
        if (mud_peer(mud, (struct sockaddr *)&peer_addr)) {
            perror("mud_peer");
            return 1;
        }
    }

    const int ctl_fd = ctl_create(GT_RUNDIR, tun_name);

    if (ctl_fd == -1) {
        perror("ctl_create");
        return 1;
    }

    const int mud_fd = mud_get_fd(mud);

    fd_set_nonblock(tun_fd);
    fd_set_nonblock(mud_fd);
    fd_set_nonblock(ctl_fd);

    const long pid = (long)getpid();

    gt_log("running on device %s as pid %li\n", tun_name, pid);

    fd_set rfds;
    FD_ZERO(&rfds);

    const int last_fd = 1 + MAX(tun_fd, MAX(mud_fd, ctl_fd));

    while (!gt_quit) {
        FD_SET(tun_fd, &rfds);
        FD_SET(mud_fd, &rfds);
        FD_SET(ctl_fd, &rfds);

        struct timeval tv = {
            .tv_sec  = sync / 1000UL,
        };

        const int ret = select(last_fd, &rfds, NULL, NULL, sync ? &tv : NULL);

        if (ret == -1) {
            if (errno == EBADF) {
                perror("select");
                break;
            }
            continue;
        }

        mtu = gt_setup_mtu(mud, tun_name);

        if (FD_ISSET(ctl_fd, &rfds)) {
            struct ctl_msg req, res = {.reply = 1};
            struct sockaddr_storage ss;
            socklen_t sl = sizeof(ss);

            ssize_t r = recvfrom(ctl_fd, &req, sizeof(req), 0,
                                 (struct sockaddr *)&ss, &sl);

            if (r == (ssize_t)sizeof(req)) {
                res.type = req.type;

                switch (req.type) {
                case CTL_NONE:
                    break;
                case CTL_STATE:
                    if (mud_set_state(mud, (struct sockaddr *)&req.path.addr, req.path.state))
                        res.ret = errno;
                    break;
                case CTL_PATH_STATUS:
                    {
                        unsigned count = 0;
                        struct mud_path *paths = mud_get_paths(mud, &count);

                        if (!paths) {
                            res.ret = errno;
                            break;
                        }

                        res.ret = EAGAIN;

                        for (unsigned i = 0; i < count; i++) {
                            memcpy(&res.path_status, &paths[i], sizeof(struct mud_path));
                            if (sendto(ctl_fd, &res, sizeof(res), 0,
                                       (const struct sockaddr *)&ss, sl) == -1)
                                perror("sendto(ctl)");
                        }

                        free(paths);
                        res.ret = 0;
                    }
                    break;
                case CTL_MTU:
                    mud_set_mtu(mud, req.mtu);
                    mtu = gt_setup_mtu(mud, tun_name);
                    res.mtu = mtu;
                    break;
                case CTL_TC:
                    if (mud_set_tc(mud, req.tc))
                        res.ret = errno;
                    break;
                case CTL_KXTIMEOUT:
                    if (mud_set_keyx_timeout(mud, req.ms))
                        res.ret = errno;
                    break;
                case CTL_TIMEOUT:
                    if (mud_set_send_timeout(mud, req.ms))
                        res.ret = errno;
                    break;
                case CTL_TIMETOLERANCE:
                    if (mud_set_time_tolerance(mud, req.ms))
                        res.ret = errno;
                    break;
                case CTL_STATUS:
                    res.status.pid = pid;
                    res.status.mtu = mtu;
                    res.status.chacha = chacha;
                    res.status.bind = bind_addr;
                    res.status.peer = peer_addr;
                    break;
                case CTL_SYNC:
                    res.ms = mud_sync(mud);
                    break;
                }
                if (sendto(ctl_fd, &res, sizeof(res), 0,
                           (const struct sockaddr *)&ss, sl) == -1)
                    perror("sendto(ctl)");
            } else if (r == -1 && errno != EAGAIN) {
                perror("recvfrom(ctl)");
            }
        }

        if (FD_ISSET(tun_fd, &rfds)) {
            struct ip_common ic;
            const int r = tun_read(tun_fd, buf, bufsize);

            if (!ip_get_common(&ic, buf, r)) {
                unsigned char hash[crypto_shorthash_BYTES];
                crypto_shorthash(hash, (const unsigned char *)&ic, sizeof(ic), hashkey);

                unsigned h;
                memcpy(&h, hash, sizeof(h));

                mud_send(mud, buf, r, (h << 8) | ic.tc);
            }
        }

        if (FD_ISSET(mud_fd, &rfds)) {
            const int r = mud_recv(mud, buf, bufsize);

            if (ip_is_valid(buf, r))
                tun_write(tun_fd, buf, r);
        }

        if (!ret)
            mud_sync(mud);
    }

    if (gt_reload && tun_fd >= 0) {
        if (tun_set_persist(tun_fd, 1) == -1)
            perror("tun_set_persist");
    }

    mud_delete(mud);
    ctl_delete(ctl_fd);
    free(buf);

    return 0;
}
