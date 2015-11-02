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

#include <sodium.h>

#define GT_BUFFER_SIZE (4*1024*1024)

struct option {
    char *name;
    void *data;
    int (*call) (void *, int, char **);
};

struct netio {
    int fd;
    buffer_t recv;
    buffer_t send; // TODO
};

struct crypto_ctx {
    crypto_aead_aes256gcm_state state;
    uint8_t nonce_w[crypto_aead_aes256gcm_NPUBBYTES];
    uint8_t nonce_r[crypto_aead_aes256gcm_NPUBBYTES];
};

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
    int ret = connect(fd, ai->ai_addr, ai->ai_addrlen);

    if (ret==-1 && errno==EINTR)
        return 0;

    return ret;
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

static int sk_accept (int fd)
{
    struct sockaddr_storage addr_storage;
    struct sockaddr *addr = (struct sockaddr *)&addr_storage;
    socklen_t addr_size = sizeof(addr_storage);

    int ret = accept(fd, addr, &addr_size);

    if (ret==-1 && errno!=EINTR)
        perror("accept");

    return ret;
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

static ssize_t fd_read (int fd, void *data, size_t size)
{
    if (!size)
        return -2;

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
    if (!size)
        return -2;

    ssize_t ret = write(fd, data, size);

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;
        if (errno)
            perror("write");
        return 0;
    }

    return ret;
}

static ssize_t fd_read_all (int fd, void *data, size_t size)
{
    size_t done = 0;

    struct pollfd pollfd = {
        .fd = fd,
        .events = POLLIN,
    };

    while (done<size) {
        ssize_t ret = fd_read(fd, data+done, size-done);

        if (!ret)
            break;

        if (ret<0) {
            poll(&pollfd, 1, -1);
            continue;
        }

        done += ret;
    }

    return done;
}

static ssize_t fd_write_all (int fd, const void *data, size_t size)
{
    size_t done = 0;

    struct pollfd pollfd = {
        .fd = fd,
        .events = POLLOUT,
    };

    while (done<size) {
        ssize_t ret = fd_write(fd, data+done, size-done);

        if (!ret)
            break;

        if (ret<0) {
            poll(&pollfd, 1, -1);
            continue;
        }

        done += ret;
    }

    return done;
}

static int encrypt_packet (struct crypto_ctx *ctx, uint8_t *packet, size_t size, buffer_t *buffer)
{
    const size_t ws = size + crypto_aead_aes256gcm_ABYTES;

    if (buffer_write_size(buffer) < ws)
        return 1;

    const int hs = 4;

    byte_cpy(buffer->write, packet, size);

    crypto_aead_aes256gcm_encrypt_afternm(
            buffer->write + hs, NULL,
            packet + hs, size - hs,
            packet, hs,
            NULL, ctx->nonce_w,
            (const crypto_aead_aes256gcm_state *)&ctx->state);

    sodium_increment(ctx->nonce_w, crypto_aead_aes256gcm_NPUBBYTES);
    buffer->write += ws;

    return 0;
}

static int decrypt_packet (struct crypto_ctx *ctx, uint8_t *packet, size_t size, buffer_t *buffer)
{
    const size_t rs = size + crypto_aead_aes256gcm_ABYTES;

    if (buffer_read_size(buffer) < rs)
        return 1;

    const int hs = 4;

    byte_cpy(packet, buffer->read, hs);

    if (crypto_aead_aes256gcm_decrypt_afternm(
                packet + hs, NULL,
                NULL,
                buffer->read + hs, rs - hs,
                packet, hs,
                ctx->nonce_r,
                (const crypto_aead_aes256gcm_state *)&ctx->state))
        return -1;

    sodium_increment(ctx->nonce_r, crypto_aead_aes256gcm_NPUBBYTES);
    buffer->read += rs;

    return 0;
}

static int option_flag (void *data, _unused_ int argc, _unused_ char **argv)
{
    const int one = 1;
    byte_cpy(data, &one, sizeof(one));

    return 0;
}

static int option_str (void *data, int argc, char **argv)
{
    if (argc<2 || !argv[1]) {
        printf("option `%s' need a string argument\n", argv[0]);
        return -1;
    }

    byte_cpy(data, &argv[1], sizeof(argv[1]));

    return 1;
}

_unused_
static int option_long (void *data, int argc, char **argv)
{
    if (argc<2 || !argv[1]) {
        printf("option `%s' need an integer argument\n", argv[0]);
        return -1;
    }

    errno = 0;
    char *end;
    long val = strtol(argv[1], &end, 0);

    if (errno || argv[1]==end) {
        printf("argument `%s' is not a valid integer\n", argv[1]);
        return -1;
    }

    byte_cpy(data, &val, sizeof(val));

    return 1;
}

static int option_option (void *data, int argc, char **argv)
{
    struct option *opt = (struct option *)data;

    for (int i=1; i<argc; i++) {
        int found = 0;

        for (int k=0; opt[k].name; k++) {
            if (str_cmp(opt[k].name, argv[i]))
                continue;

            int ret = opt[k].call(opt[k].data, argc-i, &argv[i]);

            if (ret<0)
                return -1;

            i += ret;
            found = 1;
            break;
        }

        if (!found)
            return i-1;
    }

    return argc;
}

static int option (struct option *opts, int argc, char **argv)
{
    int ret = option_option(opts, argc, argv);

    if (ret==argc)
        return 0;

    if (ret>=0)
        printf("option `%s' is unknown\n", argv[ret+1]);

    return 1;
}

static void set_ip_size (uint8_t *data, size_t size)
{
    data[2] = 0xFF&(size>>8);
    data[3] = 0xFF&(size);
}

static ssize_t get_ip_size (const uint8_t *data, size_t size)
{
    if (size<20)
        return -1;

    if ((data[0]>>4)==4)
        return (data[2]<<8)|data[3];

    return 0;
}

static void gt_setup_crypto (struct crypto_ctx *ctx, int fd, int listener)
{
    unsigned char secret[crypto_scalarmult_SCALARBYTES];
    unsigned char shared[crypto_scalarmult_BYTES];

    unsigned char public_w[crypto_scalarmult_SCALARBYTES];
    unsigned char public_r[crypto_scalarmult_SCALARBYTES];

    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];

    randombytes_buf(secret, sizeof(secret));
    crypto_scalarmult_base(public_w, secret);

    if (!listener)
        fd_write_all(fd, public_w, sizeof(public_w));

    fd_read_all(fd, public_r, sizeof(public_r));

    if (listener)
        fd_write_all(fd, public_w, sizeof(public_w));

    crypto_scalarmult(shared, secret, public_r);

    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(key));
    crypto_generichash_update(&state, shared, sizeof(shared));
    crypto_generichash_update(&state, listener?public_w:public_r, sizeof(public_w));
    crypto_generichash_update(&state, listener?public_r:public_w, sizeof(public_w));
    crypto_generichash_final(&state, key, sizeof(key));

    crypto_aead_aes256gcm_beforenm(&ctx->state, key);

    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(shared, sizeof(shared));

    sodium_memzero(public_w, sizeof(public_w));
    sodium_memzero(public_r, sizeof(public_r));

    sodium_memzero(key, sizeof(key));

    randombytes_buf(ctx->nonce_w, sizeof(ctx->nonce_w));

    fd_write_all(fd, ctx->nonce_w, sizeof(ctx->nonce_w));
    fd_read_all(fd, ctx->nonce_r, sizeof(ctx->nonce_r));
}

int main (int argc, char **argv)
{
    gt_set_signal();

    if (sodium_init()==-1) {
        printf("libsodium initialization has failed!\n");
        return -1;
    }

    if (!crypto_aead_aes256gcm_is_available()) {
        printf("AES-256-GCM is not available on your platform!\n");
        return -1;
    }

    char *host = NULL;
    char *port = "5000";
    char *dev  = "glorytun";
    int listener = 0;
    char *congestion = NULL;

    struct option opts[] = {
        { "dev",        &dev,        option_str  },
        { "host",       &host,       option_str  },
        { "port",       &port,       option_str  },
        { "listener",   &listener,   option_flag },
        { "congestion", &congestion, option_str  },
        { NULL },
    };

    if (option(opts, argc, argv))
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

    struct netio tun  = { .fd = -1 };
    struct netio sock = { .fd = -1 };

    tun.fd = tun_create(dev);

    if (tun.fd==-1)
        return 1;

    fd_set_nonblock(tun.fd);

    buffer_setup(&tun.recv, NULL, GT_BUFFER_SIZE);
    buffer_setup(&sock.recv, NULL, GT_BUFFER_SIZE);

    int fd = -1;

    if (listener) {
        fd = sk_create(ai, sk_listen);

        if (fd==-1)
            return 1;
    }

    while (running) {
        sock.fd = listener?sk_accept(fd):sk_create(ai, sk_connect);

        if (sock.fd==-1) {
            usleep(100000);
            continue;
        }

        fd_set_nonblock(sock.fd);
        sk_set_nodelay(sock.fd);
        sk_set_congestion(sock.fd, congestion);

        struct crypto_ctx ctx;
        gt_setup_crypto(&ctx, sock.fd, listener);

        printf("running...\n");

        struct pollfd fds[] = {
            { .fd = tun.fd,  .events = POLLIN },
            { .fd = sock.fd, .events = POLLIN },
        };

        struct {
            uint8_t buf[2048];
            size_t size;
        } tunr, tunw;

        tunr.size = 0;
        tunw.size = 0;

        while (running) {
            if (poll(fds, COUNT(fds), -1)==-1 && errno!=EINTR) {
                perror("poll");
                return 1;
            }

            buffer_shift(&tun.recv);

            if (fds[0].revents & POLLIN) {
                while (1) {
                    if (buffer_write_size(&tun.recv)<sizeof(tunr.buf)+16)
                        break;

                    ssize_t r = fd_read(fds[0].fd, tunr.buf, sizeof(tunr.buf));

                    if (!r)
                        return 2;

                    if (r<0)
                        break;

                    ssize_t ip_size = get_ip_size(tunr.buf, sizeof(tunr.buf));

                    if (ip_size<=0 || r>ip_size)
                        continue;

                    if (r<ip_size)
                        set_ip_size(tunr.buf, r);

                    encrypt_packet(&ctx, tunr.buf, r, &tun.recv);
                }
            }

            if (fds[1].revents & POLLOUT)
                fds[1].events = POLLIN;

            if (buffer_read_size(&tun.recv)) {
                ssize_t r = fd_write(fds[1].fd, tun.recv.read, buffer_read_size(&tun.recv));

                if (!r)
                    goto restart;

                if (r==-1)
                    fds[1].events = POLLIN|POLLOUT;

                if (r>0)
                    tun.recv.read += r;
            }

            buffer_shift(&sock.recv);

            if (fds[1].revents & POLLIN) {
                ssize_t r = fd_read(fds[1].fd, sock.recv.write, buffer_write_size(&sock.recv));

                if (!r)
                    goto restart;

                if (r>0)
                    sock.recv.write += r;
            }

            if (fds[0].revents & POLLOUT)
                fds[0].events = POLLIN;

            while (1) {
                if (!tunw.size) {
                    size_t size = buffer_read_size(&sock.recv);
                    ssize_t ip_size = get_ip_size(sock.recv.read, size);

                    if (!ip_size)
                        goto restart;

                    if (ip_size<0 || (size_t)ip_size+16>size)
                        break;

                    if (decrypt_packet(&ctx, tunw.buf, ip_size, &sock.recv)) {
                        printf("message could not be verified!\n");
                        goto restart;
                    }

                    tunw.size = ip_size;
                }
                if (tunw.size) {
                    ssize_t r = fd_write(fds[0].fd, tunw.buf, tunw.size);

                    if (!r)
                        return 2;

                    if (r==-1)
                        fds[0].events = POLLIN|POLLOUT;

                    if (r<0)
                        break;

                    tunw.size = 0;
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
