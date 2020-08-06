#include "common.h"
#include "ctl.h"
#include "iface.h"
#include "ip.h"
#include "tun.h"

#include <fcntl.h>
#include <sys/select.h>

#include "../argz/argz.h"
#include "../mud/mud.h"

#include <sodium.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int
fd_set_nonblock(int fd)
{
    if (fd == -1)
        return 0;

    int ret;

    do {
        ret = fcntl(fd, F_GETFL, 0);
    } while (ret == -1 && errno == EINTR);

    int flags = (ret == -1) ? 0 : ret;

    do {
        ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    } while (ret == -1 && errno == EINTR);

    return ret;
}

static int
gt_setup_secretkey(struct mud *mud, const char *keyfile)
{
    int fd;

    do {
        fd = open(keyfile, O_RDONLY | O_CLOEXEC);
    } while (fd == -1 && errno == EINTR);

    if (fd == -1) {
        gt_log("couldn't open %s: %s\n", keyfile, strerror(errno));
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

        size += (size_t)r;
    }

    close(fd);

    if (size != sizeof(buf)) {
        gt_log("couldn't read secret key\n");
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
gt_setup_mtu(struct mud *mud, size_t old, const char *tun_name)
{
    size_t mtu = mud_get_mtu(mud);

    if (!mtu || mtu == old)
        return mtu;

    if (iface_set_mtu(tun_name, mtu) == -1)
        gt_log("couldn't setup MTU at %zu on device %s\n", mtu, tun_name);

    return mtu;
}

int
gt_bind(int argc, char **argv)
{
    struct sockaddr_storage bind_addr = {.ss_family = AF_INET};
    struct sockaddr_storage peer_addr = {0};
    unsigned short bind_port = 5000;
    unsigned short peer_port = bind_port;
    const char *dev = NULL;
    const char *keyfile = NULL;

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
        {NULL}};

    if (argz(bindz, argc, argv))
        return 1;

    if (EMPTY(keyfile)) {
        gt_log("a keyfile is needed!\n");
        return 1;
    }

    gt_set_port((struct sockaddr *)&bind_addr, bind_port);
    gt_set_port((struct sockaddr *)&peer_addr, peer_port);

    int chacha = argz_is_set(bindz, "chacha");
    int persist = argz_is_set(bindz, "persist");

    if (sodium_init() == -1) {
        gt_log("couldn't init sodium\n");
        return 1;
    }

    unsigned char hashkey[crypto_shorthash_KEYBYTES];
    randombytes_buf(hashkey, sizeof(hashkey));

    struct mud *mud = mud_create((struct sockaddr *)&bind_addr);
    const int mud_fd = mud_get_fd(mud);

    if (mud_fd == -1) {
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
    const int tun_fd = tun_create(tun_name, sizeof(tun_name), dev);

    if (tun_fd == -1) {
        gt_log("couldn't create tun device\n");
        return 1;
    }

    size_t mtu = gt_setup_mtu(mud, 0, tun_name);

    if (tun_set_persist(tun_fd, persist) == -1) {
        gt_log("couldn't %sable persist mode on device %s\n",
               persist ? "en" : "dis", tun_name);
    }

    const int ctl_fd = ctl_create(tun_name);

    if (ctl_fd == -1) {
        char dir[64];
        if (ctl_rundir(dir, sizeof(dir))) {
            gt_log("couldn't create %s/%s: %s\n",
                   dir, tun_name, strerror(errno));
        } else {
            gt_log("couldn't find a writable run/tmp directory\n");
        }
        return 1;
    }

    if (//fd_set_nonblock(tun_fd) ||
        //fd_set_nonblock(mud_fd) ||
        fd_set_nonblock(ctl_fd)) {
        gt_log("couldn't setup non-blocking fds\n");
        return 1;
    }

    const long pid = (long)getpid();

    gt_log("running on device %s as pid %li\n", tun_name, pid);

    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    int tun_can_read = 0;
    int tun_can_write = 0;
    int mud_can_read = 0;
    int mud_can_write = 0;

    int last_fd = MAX(tun_fd, mud_fd);
    last_fd = 1 + MAX(last_fd, ctl_fd);

    __attribute__((aligned(16)))
        unsigned char buf[1500];

    while (!gt_quit) {
        if (tun_can_write) FD_CLR(tun_fd, &wfds); else FD_SET(tun_fd, &wfds);
        if (mud_can_write) FD_CLR(mud_fd, &wfds); else FD_SET(mud_fd, &wfds);
        if (tun_can_read)  FD_CLR(tun_fd, &rfds); else FD_SET(tun_fd, &rfds);
        if (mud_can_read)  FD_CLR(mud_fd, &rfds); else FD_SET(mud_fd, &rfds);

        FD_SET(ctl_fd, &rfds);

        struct timeval tv = {0};
        int update = mud_update(mud);

        if (update >= 0) {
            if (mud_can_read && tun_can_write) {
            } else if (tun_can_read && mud_can_write) {
                if (update)
                    tv.tv_usec = 1000;
            } else {
                tv.tv_usec = 100000;
            }
        }

        const int ret = select(last_fd, &rfds, &wfds, NULL, update < 0 ? NULL : &tv);

        if (ret == -1) {
            if (errno == EBADF) {
                perror("select");
                break;
            }
            continue;
        }

        if (FD_ISSET(tun_fd, &rfds)) tun_can_read  = 1;
        if (FD_ISSET(tun_fd, &wfds)) tun_can_write = 1;
        if (FD_ISSET(mud_fd, &rfds)) mud_can_read  = 1;
        if (FD_ISSET(mud_fd, &wfds)) mud_can_write = 1;

        mtu = gt_setup_mtu(mud, mtu, tun_name);

        if (tun_can_read && mud_can_write && !mud_send_wait(mud)) {
            struct ip_common ic;
            int r = tun_read(tun_fd, buf, sizeof(buf));

            if (r > 0 && !ip_get_common(&ic, buf, r)) {
                mud_send(mud, buf, (size_t)r);
                mud_can_write = 0;
            }

            tun_can_read = 0;
        }

        if (mud_can_read && tun_can_write) {
            int r = mud_recv(mud, buf, sizeof(buf));

            if (r > 0 && ip_is_valid(buf, r)) {
                tun_write(tun_fd, buf, (size_t)r);
                tun_can_write = 0;
            }

            mud_can_read = 0;
        }

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
                    if (req.path.addr.ss_family) {
                        if (!gt_get_port((struct sockaddr *)&req.path.addr))
                            gt_set_port((struct sockaddr *)&req.path.addr, peer_port);
                    } else {
                        memcpy(&req.path.addr, &peer_addr, sizeof(req.path.addr));
                    }
                    if (mud_set_state(mud,
                                      (struct sockaddr *)&req.path.local_addr,
                                      (struct sockaddr *)&req.path.addr,
                                      req.path.state,
                                      req.path.rate_tx,
                                      req.path.rate_rx,
                                      req.path.beat,
                                      req.path.fixed_rate,
                                      req.path.loss_limit))
                        res.ret = errno;
                    break;
                case CTL_CONF:
                    if (mud_set_conf(mud, &req.conf))
                        res.ret = errno;
                    res.conf = req.conf;
                    break;
                case CTL_STATUS:
                    memcpy(res.status.tun_name, tun_name, sizeof(tun_name)); // XXX
                    res.status.pid = pid;
                    res.status.mtu = mtu;
                    res.status.chacha = chacha;
                    res.status.bind = bind_addr;
                    res.status.peer = peer_addr;
                    break;
                case CTL_PATH_STATUS: {
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
                } break;
                case CTL_BAD:
                    if (mud_get_bad(mud, &res.bad))
                        res.ret = errno;
                    break;
                }
                if (sendto(ctl_fd, &res, sizeof(res), 0,
                           (const struct sockaddr *)&ss, sl) == -1)
                    perror("sendto(ctl)");
            } else if (r == -1 && errno != EAGAIN) {
                perror("recvfrom(ctl)");
            }
        }
    }

    if (gt_reload && tun_fd >= 0)
        tun_set_persist(tun_fd, 1);

    mud_delete(mud);
    ctl_delete(ctl_fd);

    return 0;
}
