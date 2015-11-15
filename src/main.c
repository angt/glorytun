#include "common-static.h"
#include "option.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <poll.h>

#include <sys/time.h>
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

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define GT_BUFFER_SIZE (4*1024*1024)
#define GT_TIMEOUT     (1000)

struct netio {
    int fd;
    struct {
        buffer_t buf;
        ssize_t ret;
    } write, read;
};

struct crypto_ctx {
    struct {
        crypto_aead_aes256gcm_state state;
        uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
    } write, read;
    uint8_t skey[crypto_generichash_KEYBYTES];
};

volatile sig_atomic_t running;

static void gt_not_available (const char *name)
{
    fprintf(stderr, "%s is not available on your platform!\n", name);
}

static int64_t dt_ms (struct timeval *ta, struct timeval *tb)
{
    const int64_t s = ta->tv_sec-tb->tv_sec;
    const int64_t n = ta->tv_usec-tb->tv_usec;
    return s*1000LL+n/1000LL;
}

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

#ifdef TCP_CONGESTION
static void sk_set_congestion (int fd, const char *name)
{
    size_t len = str_len(name);

    if (!len)
        return;

    if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name, len+1)==-1)
        perror("setsockopt TCP_CONGESTION");
}
#else
static void sk_set_congestion (_unused_ int fd, _unused_ const char *name)
{
    gt_not_available("TCP_CONGESTION");
}
#endif

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
    struct sockaddr_storage addr;
    socklen_t addr_size = sizeof(addr);

    int ret = accept(fd, (struct sockaddr *)&addr, &addr_size);

    if (ret==-1 && errno!=EINTR)
        perror("accept");

    return ret;
}

static char *sk_get_name (int fd)
{
    struct sockaddr_storage addr;
    socklen_t addr_size = sizeof(addr);

    if (getpeername(fd, (struct sockaddr *)&addr, &addr_size)==-1) {
        perror("getpeername");
        return NULL;
    }

    char host[64] = {0};
    char port[32] = {0};

    int ret = getnameinfo((struct sockaddr *)&addr, addr_size,
            host, sizeof(host),
            port, sizeof(port),
            NI_NUMERICHOST|NI_NUMERICSERV);

    switch (ret) {
    case 0:
        break;
    case EAI_MEMORY:
        errno = ENOMEM;
    case EAI_SYSTEM:
        perror("getnameinfo");
        return NULL;
    }

    const char *const strs[] = {
        host, ".", port
    };

    return str_cat(strs, COUNT(strs));
}

#ifdef TCP_INFO
static socklen_t sk_get_info (int fd, struct tcp_info *ti)
{
    socklen_t len = sizeof(struct tcp_info);

    if (getsockopt(fd, SOL_TCP, TCP_INFO, ti, &len)==-1) {
        perror("getsockopt TCP_INFO");
        return 0;
    }

    return len;
}

static void print_tcp_info (const char *name, struct tcp_info *ti)
{
    fprintf(stderr,
            "%s: tcpinfo"
            " rto:%"     PRIu32 " ato:%"          PRIu32 " snd_mss:%"  PRIu32
            " rcv_mss:%" PRIu32 " unacked:%"      PRIu32 " sacked:%"   PRIu32
            " lost:%"    PRIu32 " retrans:%"      PRIu32 " fackets:%"  PRIu32
            " pmtu:%"    PRIu32 " rcv_ssthresh:%" PRIu32 " rtt:%"      PRIu32
            " rttvar:%"  PRIu32 " snd_ssthresh:%" PRIu32 " snd_cwnd:%" PRIu32
            " advmss:%"  PRIu32 " reordering:%"   PRIu32 "\n",
            name,
            ti->tcpi_rto,       ti->tcpi_ato,            ti->tcpi_snd_mss,
            ti->tcpi_rcv_mss,   ti->tcpi_unacked,        ti->tcpi_sacked,
            ti->tcpi_lost,      ti->tcpi_retrans,        ti->tcpi_fackets,
            ti->tcpi_pmtu,      ti->tcpi_rcv_ssthresh,   ti->tcpi_rtt,
            ti->tcpi_rttvar,    ti->tcpi_snd_ssthresh,   ti->tcpi_snd_cwnd,
            ti->tcpi_advmss,    ti->tcpi_reordering);
}
#endif

static struct addrinfo *ai_create (const char *host, const char *port, int listener)
{
    if (!port || !port[0]) {
        fprintf(stderr, "port is not valid\n");
        return NULL;
    }

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };

    if (listener)
        hints.ai_flags = AI_PASSIVE;

    struct addrinfo *ai = NULL;

    int ret = getaddrinfo(host, port, &hints, &ai);

    switch (ret) {
    case 0:
        return ai;
    case EAI_MEMORY:
        errno = ENOMEM;
    case EAI_SYSTEM:
        perror("getaddrinfo");
        break;
    case EAI_FAIL:
    case EAI_AGAIN:
        fprintf(stderr, "the name server returned a failure\n");
        break;
    default:
        fprintf(stderr, "%s.%s is not valid\n", host?:"", port);
    }

    return NULL;
}

#ifdef __linux__
static int tun_create (char *name, int multiqueue)
{
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd<0) {
        perror("open /dev/net/tun");
        return -1;
    }

    struct ifreq ifr = {
        .ifr_flags = IFF_TUN|IFF_NO_PI,
    };

    if (multiqueue) {
#ifdef IFF_MULTI_QUEUE
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
#else
        gt_not_available("IFF_MULTI_QUEUE");
#endif
    }

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
static int tun_create (_unused_ char *name, _unused_ int mq)
{
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
            if (!poll(&pollfd, 1, GT_TIMEOUT))
                break;
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
            if (!poll(&pollfd, 1, GT_TIMEOUT))
                break;
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
            NULL, ctx->write.nonce,
            (const crypto_aead_aes256gcm_state *)&ctx->write.state);

    sodium_increment(ctx->write.nonce, crypto_aead_aes256gcm_NPUBBYTES);
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
                ctx->read.nonce,
                (const crypto_aead_aes256gcm_state *)&ctx->read.state))
        return -1;

    sodium_increment(ctx->read.nonce, crypto_aead_aes256gcm_NPUBBYTES);
    buffer->read += rs;

    return 0;
}

static void dump_ip_header (uint8_t *data, size_t size)
{
    if (size<20)
        return;

    const char tbl[] = "0123456789ABCDEF";
    char hex[41];

    for (size_t i=0; i<20; i++) {
        hex[(i<<1)+0] = tbl[0xF&(data[i]>>4)];
        hex[(i<<1)+1] = tbl[0xF&(data[i])];
    }

    hex[40] = 0;

    fprintf(stderr, "DUMP(%zu): %s\n", size, hex);
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

static int gt_setup_secretkey (struct crypto_ctx *ctx, char *keyfile)
{
    size_t size = sizeof(ctx->skey);

    byte_set(ctx->skey, 1, size);

    if (!keyfile)
        return 0;

    int fd = open(keyfile, O_RDONLY|O_CLOEXEC);

    if (fd<0) {
        perror("open keyfile");
        return -1;
    }

    if (fd_read_all(fd, ctx->skey, size)!=size) {
        fprintf(stderr, "unable to read secret key in `%s'\n", keyfile);
        close(fd);
        return -1;
    }

    // TODO: check key

    close(fd);

    return 0;
}

static int gt_setup_crypto (struct crypto_ctx *ctx, int fd, int listener)
{
    const size_t nonce_size = crypto_aead_aes256gcm_NPUBBYTES;
    const size_t public_size = crypto_scalarmult_SCALARBYTES;
    const size_t hash_size = crypto_generichash_BYTES;
    const size_t size = nonce_size + public_size + hash_size;

    uint8_t secret[crypto_scalarmult_SCALARBYTES];
    uint8_t shared[crypto_scalarmult_BYTES];
    uint8_t key[crypto_aead_aes256gcm_KEYBYTES];

    uint8_t data_r[size], data_w[size];
    uint8_t hash[hash_size];

    randombytes_buf(data_w, nonce_size);
    randombytes_buf(secret, sizeof(secret));
    crypto_scalarmult_base(&data_w[nonce_size], secret);

    crypto_generichash(&data_w[size-hash_size], hash_size,
            data_w, size-hash_size, ctx->skey, sizeof(ctx->skey));

    if (!listener && fd_write_all(fd, data_w, size)!=size)
        return -1;

    if (fd_read_all(fd, data_r, size)!=size)
        return -1;

    crypto_generichash(hash, hash_size,
            data_r, size-hash_size, ctx->skey, sizeof(ctx->skey));

    if (sodium_memcmp(&data_r[size-hash_size], hash, hash_size))
        return -2;

    if (listener && fd_write_all(fd, data_w, size)!=size)
        return -1;

    crypto_scalarmult(shared, secret, &data_r[nonce_size]);

    crypto_generichash_state state;
    crypto_generichash_init(&state, ctx->skey, sizeof(ctx->skey), sizeof(key));
    crypto_generichash_update(&state, shared, sizeof(shared));
    crypto_generichash_update(&state, data_r, size);
    crypto_generichash_update(&state, data_w, size);
    crypto_generichash_final(&state, key, sizeof(key));
    crypto_aead_aes256gcm_beforenm(&ctx->read.state, key);

    crypto_generichash_init(&state, ctx->skey, sizeof(ctx->skey), sizeof(key));
    crypto_generichash_update(&state, shared, sizeof(shared));
    crypto_generichash_update(&state, data_w, size);
    crypto_generichash_update(&state, data_r, size);
    crypto_generichash_final(&state, key, sizeof(key));
    crypto_aead_aes256gcm_beforenm(&ctx->write.state, key);

    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(key, sizeof(key));

    byte_cpy(ctx->read.nonce, data_r, nonce_size);
    byte_cpy(ctx->write.nonce, data_w, nonce_size);

    return 0;
}

int main (int argc, char **argv)
{
    gt_set_signal();

    int listener = 0;
    char *host = NULL;
    char *port = "5000";
    char *dev = PACKAGE_NAME;
    char *keyfile = NULL;
    char *congestion = NULL;
    int delay = 0;
    int multiqueue = 0;
    int version = 0;
    int debug = 0;

#ifdef TCP_INFO
    struct {
        struct timeval time;
        struct tcp_info info;
    } tcpinfo = {0};
#endif

    struct option opts[] = {
        { "listener",   &listener,   option_flag },
        { "host",       &host,       option_str  },
        { "port",       &port,       option_str  },
        { "dev",        &dev,        option_str  },
        { "keyfile",    &keyfile,    option_str  },
        { "congestion", &congestion, option_str  },
        { "delay",      &delay,      option_flag },
        { "multiqueue", &multiqueue, option_flag },
        { "debug",      &debug,      option_flag },
        { "version",    &version,    option_flag },
        { NULL },
    };

    if (option(opts, argc, argv))
        return 1;

    if (version) {
        printf(PACKAGE_STRING"\n");
        return 0;
    }

    if (sodium_init()==-1) {
        fprintf(stderr, "libsodium initialization has failed!\n");
        return 1;
    }

    if (!crypto_aead_aes256gcm_is_available()) {
        gt_not_available("AES-256-GCM");
        return 1;
    }

    struct crypto_ctx ctx;

    if (gt_setup_secretkey(&ctx, keyfile))
        return 1;

    struct addrinfo *ai = ai_create(host, port, listener);

    if (!ai)
        return 1;

    struct netio tun  = { .fd = -1 };
    struct netio sock = { .fd = -1 };

    tun.fd = tun_create(dev, multiqueue);

    if (tun.fd==-1)
        return 1;

    fd_set_nonblock(tun.fd);

    buffer_setup(&sock.write.buf, NULL, GT_BUFFER_SIZE);
    buffer_setup(&sock.read.buf, NULL, GT_BUFFER_SIZE);

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

        char *sockname = sk_get_name(sock.fd);

        if (!sockname)
            goto restart;

        fprintf(stderr, "%s: connected\n", sockname);

        if (!delay)
            sk_set_nodelay(sock.fd);

        fd_set_nonblock(sock.fd);
        sk_set_congestion(sock.fd, congestion);

        switch (gt_setup_crypto(&ctx, sock.fd, listener)) {
            case -2: fprintf(stderr, "%s: key exchange could not be verified!\n", sockname);
            case -1: goto restart;
            default: break;
        }

        struct {
            uint8_t buf[2048];
            size_t size;
        } tunr, tunw;

        tunr.size = 0;
        tunw.size = 0;

        fd_set rfds, wfds;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        while (running) {
            FD_SET(tun.fd, &rfds);
            FD_SET(sock.fd, &rfds);

            if (select(2, &rfds, &wfds, NULL, NULL)==-1 && errno!=EINTR) {
                perror("select");
                return 1;
            }

#ifdef TCP_INFO
            struct timeval now;
            gettimeofday(&now, NULL);

            if (debug && dt_ms(&now, &tcpinfo.time)>1000LL) {
                tcpinfo.time = now;
                if (sk_get_info(sock.fd, &tcpinfo.info))
                    print_tcp_info(sockname, &tcpinfo.info);
            }
#endif

            buffer_shift(&sock.write.buf);

            if (FD_ISSET(tun.fd, &rfds)) {
                while (1) {
                    if (buffer_write_size(&sock.write.buf)<sizeof(tunr.buf)+16)
                        break;

                    ssize_t r = fd_read(tun.fd, tunr.buf, sizeof(tunr.buf));

                    if (!r)
                        return 2;

                    if (r<0)
                        break;

                    ssize_t ip_size = get_ip_size(tunr.buf, sizeof(tunr.buf));

                    if (ip_size<=0)
                        continue;

                    if (ip_size!=r) {
                        dump_ip_header(tunr.buf, r);

                        if (r<ip_size) {
                            set_ip_size(tunr.buf, r);
                        } else {
                            continue;
                        }
                    }

                    encrypt_packet(&ctx, tunr.buf, r, &sock.write.buf);
                }
            }

            if (FD_ISSET(sock.fd, &wfds))
                FD_CLR(sock.fd, &wfds);

            if (buffer_read_size(&sock.write.buf)) {
                sock.write.ret = fd_write(sock.fd, sock.write.buf.read, buffer_read_size(&sock.write.buf));

                if (!sock.write.ret)
                    goto restart;

                if (sock.write.ret==-1)
                    FD_SET(sock.fd, &wfds);

                if (sock.write.ret>0)
                    sock.write.buf.read += sock.write.ret;
            }

            buffer_shift(&sock.read.buf);

            if (FD_ISSET(sock.fd, &rfds)) {
                sock.read.ret = fd_read(sock.fd, sock.read.buf.write, buffer_write_size(&sock.read.buf));

                if (!sock.read.ret)
                    goto restart;

                if (sock.read.ret>0)
                    sock.read.buf.write += sock.read.ret;
            }

            if (FD_ISSET(tun.fd, &wfds))
                FD_CLR(tun.fd, &wfds);

            while (1) {
                if (!tunw.size) {
                    size_t size = buffer_read_size(&sock.read.buf);
                    ssize_t ip_size = get_ip_size(sock.read.buf.read, size);

                    if (!ip_size)
                        goto restart;

                    if (ip_size<0 || (size_t)ip_size+16>size)
                        break;

                    if (decrypt_packet(&ctx, tunw.buf, ip_size, &sock.read.buf)) {
                        fprintf(stderr, "%s: message could not be verified!\n", sockname);
                        goto restart;
                    }

                    tunw.size = ip_size;
                }
                if (tunw.size) {
                    ssize_t r = fd_write(tun.fd, tunw.buf, tunw.size);

                    if (!r)
                        return 2;

                    if (r==-1)
                        FD_SET(tun.fd, &wfds);

                    if (r<0)
                        break;

                    tunw.size = 0;
                }
            }
        }

    restart:
        if (sockname) {
            free(sockname);
            sockname = NULL;
        }

        close(sock.fd);
        sock.fd = -1;
    }

    freeaddrinfo(ai);

    free(sock.write.buf.data);
    free(sock.read.buf.data);

    return 0;
}
