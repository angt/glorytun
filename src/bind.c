#include "common.h"
#include "ctl.h"
#include "iface.h"
#include "ip.h"
#include "tun.h"
#include "argz.h"

#include <fcntl.h>
#include <sys/select.h>
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
gt_read_keyfile(unsigned char *key, const char *keyfile)
{
    int fd;

    do {
        fd = open(keyfile, O_RDONLY | O_CLOEXEC);
    } while (fd == -1 && errno == EINTR);

    if (fd == -1) {
        gt_log("couldn't open %s: %s\n", keyfile, strerror(errno));
        return -1;
    }
    char buf[2 * MUD_PUBKEY_SIZE];
    size_t size = 0;

    while (size < sizeof(buf)) {
        ssize_t r = read(fd, buf + size, sizeof(buf) - size);

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
    if (gt_fromhex(key, MUD_PUBKEY_SIZE, buf, sizeof(buf))) {
        gt_log("secret key is not valid\n");
        return -1;
    }
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
gt_bind(int argc, char **argv, void *data)
{
    const char *dev = NULL;
    struct argz_path keyfile = {0};
    struct gt_argz_addr local = {
        .sock.sin = {
            .sin_family = AF_INET,
            .sin_port = htons(5000),
        },
    };
    struct gt_argz_addr remote = local;

    struct argz z[] = {
        {"dev",     "Tunnel device",                  argz_str,      &dev},
        {"keyfile", "Secret file to use",             argz_path, &keyfile},
        {"from",    "Address and port to bind",    gt_argz_addr,   &local},
        {"to",      "Address and port to connect", gt_argz_addr,  &remote},
        {"persist", "Keep the tunnel device after exiting"               },
        {"chacha" , "Force fallback cipher"                              },
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    if (EMPTY(keyfile.path)) {
        gt_log("a keyfile is needed!\n");
        return -1;
    }
    const int chacha = argz_is_set(z, "chacha");
    const int persist = argz_is_set(z, "persist");

    if (sodium_init() == -1) {
        gt_log("couldn't init sodium\n");
        return -1;
    }
    unsigned char key[MUD_PUBKEY_SIZE];

    if (gt_read_keyfile(key, keyfile.path))
        return -1;

    int aes = !chacha;
    struct mud *mud = mud_create(&local.sock, key, &aes);
    const int mud_fd = mud_get_fd(mud);

    if (mud_fd == -1) {
        gt_log("couldn't create mud\n");
        return -1;
    }
    if (!chacha && !aes)
        gt_log("AES is not available, enjoy ChaCha20!\n");

    char tun_name[64];
    const int tun_fd = tun_create(tun_name, sizeof(tun_name), dev);

    if (tun_fd == -1) {
        gt_log("couldn't create tun device\n");
        return -1;
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
        return -1;
    }
    if (//fd_set_nonblock(tun_fd) ||
        //fd_set_nonblock(mud_fd) ||
        fd_set_nonblock(ctl_fd)) {
        gt_log("couldn't setup non-blocking fds\n");
        return -1;
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
            int r = tun_read(tun_fd, buf, sizeof(buf));
            if (r > 0) {
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
            struct mud_paths paths;
            union ctl_sun sun;
            socklen_t slen = sizeof(sun);
            ssize_t r = recvfrom(ctl_fd, &req, sizeof(req), 0, &sun.sa, &slen);
            if (r == -1) {
                if (errno != EAGAIN)
                    perror("recvfrom(ctl)");
            } else if (r == (ssize_t)sizeof(req)) {
                res.type = req.type;
                memcpy(res.tun_name, tun_name, sizeof(res.tun_name));
                switch (req.type) {
                case CTL_NONE:
                    break;
                case CTL_STATUS:
                    res.status.pid = pid;
                    res.status.mtu = mtu;
                    res.status.cipher = !aes;
                    res.status.local  = local.sock;
                    res.status.remote = remote.sock;
                    break;
                case CTL_CONF:
                    if (mud_set(mud, &req.conf))
                        res.ret = errno;
                    res.conf = req.conf;
                    break;
                case CTL_PATH_STATUS:
                    if (mud_get_paths(mud, &paths,
                                      &req.path.conf.local,
                                      &req.path.conf.remote)) {
                        res.ret = errno;
                        break;
                    }
                    res.ret = EAGAIN;
                    for (unsigned i = 0; i < paths.count; i++) {
                        res.path = paths.path[i];
                        if (sendto(ctl_fd, &res, sizeof(res), 0, &sun.sa, slen) == -1)
                            perror("sendto(ctl)");
                    }
                    res.ret = 0;
                    break;
                case CTL_PATH_CONF:
                    if (req.path.conf.remote.sa.sa_family) {
                        if (!gt_get_port(&req.path.conf.remote))
                            gt_set_port(&req.path.conf.remote,
                                        gt_get_port(&remote.sock));
                    } else {
                        req.path.conf.remote = remote.sock;
                    }
                    if (mud_set_path(mud, &req.path.conf))
                        res.ret = errno;
                    res.path.conf = req.path.conf;
                    break;
                case CTL_ERRORS:
                    if (mud_get_errors(mud, &res.errors))
                        res.ret = errno;
                    break;
                }
                if (sendto(ctl_fd, &res, sizeof(res), 0, &sun.sa, slen) == -1)
                    perror("sendto(ctl)");
            }
        }
    }
    if (gt_reload && tun_fd >= 0)
        tun_set_persist(tun_fd, 1);

    mud_delete(mud);
    ctl_delete(ctl_fd);

    return 0;
}
