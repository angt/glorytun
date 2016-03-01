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

#include <sodium.h>

#include "mud.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static struct {
    int timeout;
    volatile sig_atomic_t quit;
    volatile sig_atomic_t info;
    uint8_t key[crypto_generichash_KEYBYTES];
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

static int gt_setup_secretkey (char *keyfile)
{
    const size_t size = sizeof(gt.key);

    if (str_empty(keyfile)) {
        char buf[2*size+1];

        randombytes_buf(gt.key, size);
        gt_tohex(buf, sizeof(buf), gt.key, size);
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

    if (gt_fromhex(gt.key, size, key, sizeof(key))) {
        gt_log("secret key is not valid\n");
        return -1;
    }

    return 0;
}

int main (int argc, char **argv)
{
    gt_set_signal();

    char *host = NULL;
    char *port = "5000";
    char *bind_list = NULL;
    char *dev = NULL;
    char *keyfile = NULL;
    char *statefile = NULL;

    gt.timeout = 5000;

    struct option opts[] = {
        { "host",        &host,         option_str    },
        { "port",        &port,         option_str    },
        { "bind",        &bind_list,    option_str    },
        { "dev",         &dev,          option_str    },
        { "keyfile",     &keyfile,      option_str    },
        { "multiqueue",  NULL,          option_option },
        { "statefile",   &statefile,    option_str    },
        { "timeout",     &gt.timeout,   option_long   },
        { "version",     NULL,          option_option },
        { NULL },
    };

    if (option(opts, argc, argv))
        return 1;

    if (option_is_set(opts, "version")) {
        gt_print(PACKAGE_STRING"\n");
        return 0;
    }

    if (!option_is_set(opts, "keyfile")) {
        gt_log("keyfile option must be set\n");
        return 1;
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

    if (gt_setup_secretkey(keyfile))
        return 1;

    struct mud *mud = mud_create(gt.key, sizeof(gt.key));

    if (!mud) {
        gt_log("couldn't create mud\n");
        return 1;
    }

    if (bind_list) {
        char tmp[1024];
        char *name = &tmp[0];

        size_t size = str_cpy(tmp, bind_list, sizeof(tmp)-1);

        for (size_t i=0; i<size; i++) {
            if (tmp[i]!=',')
                continue;

            tmp[i] = 0;

            if (mud_bind(mud, name))
                return 1;

            name = &tmp[i+1];
        }

        if (name[0] && mud_bind(mud, name))
            return 1;
    }

    if (host && mud_peer(mud, host, port))
        return 1;

    int mud_fd = mud_get_fd(mud);

    state("INITIALIZED", tun_name);

    fd_set rfds;
    FD_ZERO(&rfds);

    unsigned char buf[2048];

    while (!gt.quit) {
        FD_SET(tun_fd, &rfds);
        FD_SET(mud_fd, &rfds);

        struct timeval timeout = {
            .tv_usec = 1000,
        };

        if _0_(select(mud_fd+1, &rfds, NULL, NULL, &timeout)==-1) {
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

        if (FD_ISSET(mud_fd, &rfds))
            mud_pull(mud);

        while (1) {
            const ssize_t r = mud_recv(mud, buf, sizeof(buf));

            if (r<=0)
                break;

            tun_write(tun_fd, buf, r);
        }
    }

    return 0;
}
