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

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#define GT_FAKE_BSD
#endif

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef GT_FAKE_BSD
#undef GT_FAKE_BSD
#undef __FAVOR_BSD
#endif

#include <arpa/inet.h>
#include <netdb.h>

#include <sodium.h>

#include "mud.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static struct {
    int timeout;
} gt;

struct crypto_ctx {
    struct {
        crypto_aead_aes256gcm_state state;
        uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
    } write, read;
    uint8_t skey[crypto_generichash_KEYBYTES];
};

volatile sig_atomic_t gt_close = 0;
volatile sig_atomic_t gt_info = 0;

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
        gt_close = 1;
        break;
    case SIGUSR1:
        gt_info = 1;
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

static int gt_setup_secretkey (struct crypto_ctx *ctx, char *keyfile)
{
    const size_t size = sizeof(ctx->skey);

    if (str_empty(keyfile)) {
        char buf[2*size+1];

        randombytes_buf(ctx->skey, size);
        gt_tohex(buf, sizeof(buf), ctx->skey, size);
        state("SECRETKEY", buf);

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

    char key[2*size];
    size_t r = fd_read_all(fd, key, sizeof(key));

    close(fd);

    if (r!=sizeof(key)) {
        gt_log("unable to read secret key\n");
        return -1;
    }

    if (gt_fromhex(ctx->skey, size, key, sizeof(key))) {
        gt_log("secret key is not valid\n");
        return -1;
    }

    return 0;
}

int main (int argc, char **argv)
{
    gt_set_signal();

    char *host_bind = NULL;
    char *host_bind2 = NULL;
    char *host_peer = NULL;
    char *port = "5000";
    char *dev = NULL;
    char *keyfile = NULL;
    char *statefile = NULL;

    gt.timeout = 5000;

    struct option opts[] = {
        { "bind",        &host_bind,    option_str    },
        { "bind2",       &host_bind2,   option_str    },
        { "peer",        &host_peer,    option_str    },
        { "port",        &port,         option_str    },
        { "dev",         &dev,          option_str    },
        { "keyfile",     &keyfile,      option_str    },
        { "multiqueue",  NULL,          option_option },
        { "statefile",   &statefile,    option_str    },
        { "timeout",     &gt.timeout,   option_long   },
        { "debug",       NULL,          option_option },
        { "version",     NULL,          option_option },
        { NULL },
    };

    if (option(opts, argc, argv))
        return 1;

    if (option_is_set(opts, "version")) {
        gt_print(PACKAGE_STRING"\n");
        return 0;
    }

    int listener = 0;
    int debug = option_is_set(opts, "debug");

    if (!host_peer) {
        listener = 1;

        if (!option_is_set(opts, "keyfile")) {
            gt_log("keyfile option must be set\n");
            return 1;
        }
    }

    if (gt.timeout<=0 || gt.timeout>INT_MAX) {
        gt_log("bad timeout\n");
        return 1;
    }

    if (sodium_init()==-1) {
        gt_log("libsodium initialization has failed\n");
        return 1;
    }

    if (!crypto_aead_aes256gcm_is_available()) {
        gt_na("AES-256-GCM");
        return 1;
    }

    if (state_init(statefile))
        return 1;

    char *tun_name = NULL;

    int tun_fd = tun_create(dev, &tun_name, option_is_set(opts, "multiqueue"));

    if (tun_fd==-1) {
        gt_log("couldn't create tun device\n");
        return 1;
    }

    fd_set_nonblock(tun_fd);

    struct crypto_ctx ctx;

    if (gt_setup_secretkey(&ctx, keyfile))
        return 1;

    struct mud *mud = mud_create(ctx.skey, sizeof(ctx.skey));

    if (!mud) {
        gt_log("unable to crate the mud !!!\n");
        return 1;
    }

    int fd1 = mud_bind(mud, host_bind, port);

    if (fd1==-1)
        return 1;

    int fdmax = fd1;

    int fd2 = -1;

    if (host_bind2) {
        fd2 = mud_bind(mud, host_bind2, port);
        fdmax = fd2;
        if (fd2==-1)
            return 1;
    }

    if (host_peer && mud_peer(mud, host_peer, port))
        return 1;

    state("INITIALIZED", tun_name);

    struct packet *packet = NULL;

    while (!gt_close) {
        state("STARTED", NULL);

        fd_set rfds;
        FD_ZERO(&rfds);

        int stop_loop = 0;
        unsigned char buf[2048];

        while (!gt_close) {
            FD_SET(tun_fd, &rfds);
            FD_SET(fd1, &rfds);

            if (fd2!=-1)
                FD_SET(fd2, &rfds);

            struct timeval timeout = {
                .tv_usec = 1000,
            };

            if _0_(select(fdmax+1, &rfds, NULL, NULL, &timeout)==-1) {
                if (errno==EINTR)
                    continue;
                perror("select");
                return 1;
            }

            if (FD_ISSET(tun_fd, &rfds)) {
                while (1) {
                    const ssize_t r = tun_read(tun_fd, buf, sizeof(buf));

                    if (r<=0)
                        break;

                    struct ip_common ic;

                    if (!ip_get_common(&ic, buf, sizeof(buf)) && ic.size==r)
                        mud_send(mud, buf, r);
                }
            }

            mud_push(mud);

            if (FD_ISSET(fd2, &rfds) || FD_ISSET(fd1, &rfds))
                mud_pull(mud);

            while (1) {
                const ssize_t r = mud_recv(mud, buf, sizeof(buf));

                if (r<=0)
                    break;

                tun_write(tun_fd, buf, r);
            }
        }

    restart:
        state("STOPPED", NULL);
    }

    return 0;
}
