#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sodium.h>

#include "common-static.h"
#include "ip-static.h"

#include "option.h"
#include "tun.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define GT_BUFFER_SIZE  (4*1024*1024)
#define GT_TIMEOUT      (5000)
#define GT_MTU_MAX      (1500)
#define GT_TUNR_SIZE    (0x7FFF-16)
#define GT_TUNW_SIZE    (0x7FFF)

struct fdbuf {
    int fd;
    buffer_t read;
    buffer_t write;
};

struct blk {
    size_t size;
    uint8_t data[GT_MTU_MAX] _align_(16);
};

struct crypto_ctx {
    struct {
        crypto_aead_aes256gcm_state state;
        uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
    } write, read;
    uint8_t skey[crypto_generichash_KEYBYTES];
};

volatile sig_atomic_t gt_close = 0;
volatile sig_atomic_t gt_info = 0;

_pure_
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

enum sk_opt {
    sk_nodelay,
    sk_reuseaddr,
    sk_keepalive,
    sk_keepcnt,
    sk_keepidle,
    sk_keepintvl,
    sk_congestion,
    sk_defer_accept,
    sk_quickack,
};

static void sk_set (int fd, enum sk_opt opt, const void *val, socklen_t len)
{
    if (!val || len<=0)
        return;

    struct {
        const char *name;
        const int present;
        const int level;
        const int option;
    } opts[] = {
        [sk_nodelay] = { "TCP_NODELAY", 1, IPPROTO_TCP, TCP_NODELAY, },
        [sk_reuseaddr] = { "SO_REUSEADDR", 1, SOL_SOCKET, SO_REUSEADDR, },
        [sk_keepalive] = { "SO_KEEPALIVE", 1, SOL_SOCKET, SO_KEEPALIVE, },
        [sk_keepcnt] = { "TCP_KEEPCNT",
#ifdef TCP_KEEPCNT
            1, IPPROTO_TCP, TCP_KEEPCNT,
#endif
        },
        [sk_keepidle] = { "TCP_KEEPIDLE",
#ifdef TCP_KEEPIDLE
            1, IPPROTO_TCP, TCP_KEEPIDLE,
#endif
        },
        [sk_keepintvl] = { "TCP_KEEPINTVL",
#ifdef TCP_KEEPINTVL
            1, IPPROTO_TCP, TCP_KEEPINTVL,
#endif
        },
        [sk_congestion] = { "TCP_CONGESTION",
#ifdef TCP_CONGESTION
            1, IPPROTO_TCP, TCP_CONGESTION,
#endif
        },
        [sk_defer_accept] = { "TCP_DEFER_ACCEPT",
#ifdef TCP_DEFER_ACCEPT
            1, IPPROTO_TCP, TCP_DEFER_ACCEPT,
#endif
        },
        [sk_quickack] = { "TCP_QUICKACK",
#ifdef TCP_QUICKACK
            1, IPPROTO_TCP, TCP_QUICKACK,
#endif
        },
    };

    if (!opts[opt].present) {
        gt_na(opts[opt].name);
        return;
    }

    if (setsockopt(fd, opts[opt].level, opts[opt].option, val, len)==-1)
        gt_log("couldn't set socket option `%s'\n", opts[opt].name);
}

static void sk_set_int (int fd, enum sk_opt opt, int val)
{
    return sk_set(fd, opt, &val, sizeof(val));
}

static int sk_listen (int fd, struct addrinfo *ai)
{
    sk_set_int(fd, sk_reuseaddr, 1);

    int ret = bind(fd, ai->ai_addr, ai->ai_addrlen);

    if (ret==-1) {
        perror("bind");
        return -1;
    }

    ret = listen(fd, 8);

    if (ret==-1) {
        perror("listen");
        return -1;
    }

    sk_set_int(fd, sk_defer_accept, GT_TIMEOUT/1000);

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

static struct addrinfo *ai_create (const char *host, const char *port, int listener)
{
    if (!port || !port[0]) {
        gt_log("port is not valid\n");
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
        gt_log("the name server returned a failure\n");
        break;
    default:
        gt_log("%s.%s is not valid\n", host?:"", port);
    }

    return NULL;
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
    if (!size)
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
    if (!size)
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

static ssize_t fd_read_all (int fd, void *data, size_t size)
{
    size_t done = 0;

    struct pollfd pollfd = {
        .fd = fd,
        .events = POLLIN,
    };

    while (done<size) {
        ssize_t ret = fd_read(fd, (uint8_t *)data+done, size-done);

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
        ssize_t ret = fd_write(fd, (const uint8_t *)data+done, size-done);

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

static int gt_encrypt (struct crypto_ctx *ctx, buffer_t *dst, buffer_t *src)
{
    const size_t rs = buffer_read_size(src);
    const size_t ws = buffer_write_size(dst);

    if (!rs || !ws)
        return 0;

    const size_t size = rs+crypto_aead_aes256gcm_ABYTES;

    if (size+2>ws)
        return 0;

    dst->write[0] = 0xFF&(size>>8);
    dst->write[1] = 0xFF&(size);

    crypto_aead_aes256gcm_encrypt_afternm(
            dst->write+2, NULL,
            src->read, rs,
            dst->write, 2,
            NULL, ctx->write.nonce,
            (const crypto_aead_aes256gcm_state *)&ctx->write.state);

    sodium_increment(ctx->write.nonce, crypto_aead_aes256gcm_NPUBBYTES);

    src->read += rs;
    dst->write += size+2;

    return 0;
}

static int gt_decrypt (struct crypto_ctx *ctx, buffer_t *dst, buffer_t *src)
{
    const size_t rs = buffer_read_size(src);
    const size_t ws = buffer_write_size(dst);

    if (!rs || !ws)
        return 0;

    if (rs<=2+crypto_aead_aes256gcm_ABYTES)
        return 0;

    const size_t size = (src->read[0]<<8)|src->read[1];

    if (size-crypto_aead_aes256gcm_ABYTES>ws)
        return 0;

    if (size+2>rs)
        return 0;

    if (crypto_aead_aes256gcm_decrypt_afternm(
                dst->write, NULL,
                NULL,
                src->read+2, size,
                src->read, 2,
                ctx->read.nonce,
                (const crypto_aead_aes256gcm_state *)&ctx->read.state))
        return -1;

    sodium_increment(ctx->read.nonce, crypto_aead_aes256gcm_NPUBBYTES);

    src->read += size+2;
    dst->write += size-crypto_aead_aes256gcm_ABYTES;

    return 0;
}

static void gt_dump (uint8_t *dst, size_t dst_size, uint8_t *src, size_t src_size)
{
    if (dst_size<2*src_size+1)
        return;

    const char tbl[] = "0123456789ABCDEF";

    for (size_t i=0; i<src_size; i++) {
        dst[(i<<1)+0] = tbl[0xF&(src[i]>>4)];
        dst[(i<<1)+1] = tbl[0xF&(src[i])];
    }

    dst[2*src_size] = 0;
}

static void gt_print_hdr (uint8_t *data, size_t ip_size, const char *sockname)
{
    const int ip_version = ip_get_version(data, GT_MTU_MAX);
    const ssize_t ip_proto = ip_get_proto(data, GT_MTU_MAX);
    const ssize_t ip_hdr_size = ip_get_hdr_size(data, GT_MTU_MAX);

    uint8_t ip_src[33];
    uint8_t ip_dst[33];

    switch (ip_version) {
        case 4:
            gt_dump(ip_src, sizeof(ip_src), &data[12], 4);
            gt_dump(ip_dst, sizeof(ip_dst), &data[16], 4);
            break;
        case 6:
            gt_dump(ip_src, sizeof(ip_src), &data[9], 16);
            gt_dump(ip_dst, sizeof(ip_dst), &data[25], 16);
            break;
    }

    gt_log("%s: version=%i size=%zi proto=%zi src=%s dst=%s\n", sockname, ip_version, ip_size, ip_proto, ip_src, ip_dst);

    if (ip_hdr_size<=0 || ip_proto!=6)
        return;

    struct tcphdr tcp;

    byte_cpy(&tcp, &data[ip_hdr_size], sizeof(tcp));

    tcp.source = ntohs(tcp.source);
    tcp.dest = ntohs(tcp.dest);
    tcp.seq = ntohl(tcp.seq);
    tcp.ack_seq = ntohl(tcp.ack_seq);
    tcp.window = ntohs(tcp.window);

    gt_log("%s: tcp src=%i dst=%i seq=%u ack=%u win=%u %s%s%s%s%s%s\n",
            sockname, tcp.source, tcp.dest, tcp.seq, tcp.ack_seq, tcp.window,
            tcp.fin?"FIN ":"", tcp.syn?"SYN ":"", tcp.rst?"RST ":"",
            tcp.psh?"PSH ":"", tcp.ack?"ACK ":"", tcp.urg?"URG ":"");
}

static int gt_setup_secretkey (struct crypto_ctx *ctx, char *keyfile)
{
    const size_t size = sizeof(ctx->skey);

    byte_set(ctx->skey, 1, size);

    if (!keyfile)
        return 0;

    int fd;

    do {
        fd = open(keyfile, O_RDONLY|O_CLOEXEC);
    } while (fd==-1 && errno==EINTR);

    if (fd==-1) {
        perror("open keyfile");
        return -1;
    }

    if (fd_read_all(fd, ctx->skey, size)!=size) {
        gt_log("unable to read secret key in `%s'\n", keyfile);
        close(fd);
        return -1;
    }

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
    uint8_t auth_r[hash_size], auth_w[hash_size];
    uint8_t hash[hash_size];

    crypto_generichash_state state;

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

    crypto_generichash(auth_w, hash_size,
            data_r, size, ctx->skey, sizeof(ctx->skey));

    if (fd_write_all(fd, auth_w, hash_size)!=hash_size)
        return -1;

    if (fd_read_all(fd, auth_r, hash_size)!=hash_size)
        return -1;

    crypto_generichash(hash, hash_size,
            data_w, size, ctx->skey, sizeof(ctx->skey));

    if (sodium_memcmp(auth_r, hash, hash_size))
        return -2;

    if (crypto_scalarmult(shared, secret, &data_r[nonce_size]))
        return -2;

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

    char *host = NULL;
    char *port = "5000";
    char *dev = PACKAGE_NAME;
    char *keyfile = NULL;
    char *congestion = NULL;

    long buffer_size = GT_BUFFER_SIZE;

    long ka_count = -1;
    long ka_idle = -1;
    long ka_interval = -1;

    long retry_count = 0;
    long retry_slope = 1000;
    long retry_const = 0;
    long retry_limit = 1000000;

    struct option ka_opts[] = {
        { "count",    &ka_count,    option_long },
        { "idle",     &ka_idle,     option_long },
        { "interval", &ka_interval, option_long },
        { NULL },
    };

    struct option retry_opts[] = {
        { "count", &retry_count, option_long },
        { "slope", &retry_slope, option_long },
        { "const", &retry_const, option_long },
        { "limit", &retry_limit, option_long },
        { NULL },
    };

    struct option opts[] = {
        { "listener",    NULL,         option_option },
        { "host",        &host,        option_str    },
        { "port",        &port,        option_str    },
        { "dev",         &dev,         option_str    },
        { "keyfile",     &keyfile,     option_str    },
        { "congestion",  &congestion,  option_str    },
        { "delay",       NULL,         option_option },
        { "multiqueue",  NULL,         option_option },
        { "keepalive",   ka_opts,      option_option },
        { "buffer-size", &buffer_size, option_long   },
        { "noquickack",  NULL,         option_option },
        { "retry",       &retry_opts,  option_option },
        { "daemon",      NULL,         option_option },
        { "debug",       NULL,         option_option },
        { "version",     NULL,         option_option },
        { NULL },
    };

    if (option(opts, argc, argv))
        return 1;

    if (option_is_set(opts, "version")) {
        gt_print(PACKAGE_STRING"\n");
        return 0;
    }

    const int listener = option_is_set(opts, "listener");
    const int delay = option_is_set(opts, "delay");
    const int keepalive = option_is_set(opts, "keepalive");
    const int noquickack = option_is_set(opts, "noquickack");
    const int debug = option_is_set(opts, "debug");

    if (buffer_size < 2048) {
        buffer_size = 2048;
        gt_log("buffer size must be greater than 2048!\n");
    }

    if (sodium_init()==-1) {
        gt_log("libsodium initialization has failed!\n");
        return 1;
    }

    if (!crypto_aead_aes256gcm_is_available()) {
        gt_na("AES-256-GCM");
        return 1;
    }

    struct crypto_ctx ctx;

    if (gt_setup_secretkey(&ctx, keyfile))
        return 1;

    struct addrinfo *ai = ai_create(host, port, listener);

    if (!ai)
        return 1;

    struct fdbuf tun  = { .fd = -1 };
    struct fdbuf sock = { .fd = -1 };

    tun.fd = tun_create(dev, option_is_set(opts, "multiqueue"));

    if (tun.fd==-1)
        return 1;

    struct blk *blks = calloc(256, sizeof(struct blk));
    size_t blk_count = 0;
    uint8_t blk_read = 0;
    uint8_t blk_write = 0;

    if (!blks)
        return 1;

    fd_set_nonblock(tun.fd);

    buffer_setup(&tun.write, NULL, GT_TUNW_SIZE);
    buffer_setup(&tun.read,  NULL, GT_TUNR_SIZE);

    buffer_setup(&sock.write, NULL, buffer_size);
    buffer_setup(&sock.read,  NULL, buffer_size);

    int fd = -1;

    if (listener) {
        fd = sk_create(ai, sk_listen);

        if (fd==-1)
            return 1;
    }

    if (option_is_set(opts, "daemon")) {
        switch (fork()) {
        case -1:
            perror("fork");
            return 1;
        case 0:
            if (setsid()==-1)
                perror("setsid");
            break;
        default:
            _exit(0);
        }

        chdir("/");
    }

    long retry = 0;

    while (!gt_close) {
        sock.fd = listener?sk_accept(fd):sk_create(ai, sk_connect);

        if (sock.fd==-1) {
            if (retry<LONG_MAX)
                retry++;

            long usec = retry*retry_slope+retry_const;

            if (retry_count>=0 && retry>=retry_count) {
                gt_log("couldn't %s (%d attempt%s)\n",
                        listener?"listen":"connect",
                        (int)retry, (retry>1)?"s":"");
                break;
            }

            if (usec>retry_limit)
                usec = retry_limit;

            if (usec<=0)
                usec = 0;

            if (usleep(usec)==-1 && errno==EINVAL)
                sleep(usec/1000000);

            continue;
        }

        char *sockname = sk_get_name(sock.fd);

        if (!sockname) {
            close(sock.fd);
            continue;
        }

        gt_log("%s: connected\n", sockname);

        fd_set_nonblock(sock.fd);

        sk_set_int(sock.fd, sk_nodelay, !delay);
        sk_set_int(sock.fd, sk_keepalive, keepalive);

        if (keepalive) {
            if (ka_count>=0 && ka_count<=INT_MAX)
                sk_set_int(sock.fd, sk_keepcnt, ka_count);

            if (ka_idle>=0 && ka_idle<=INT_MAX)
                sk_set_int(sock.fd, sk_keepidle, ka_idle);

            if (ka_interval>=0 && ka_interval<=INT_MAX)
                sk_set_int(sock.fd, sk_keepintvl, ka_interval);
        }

        sk_set(sock.fd, sk_congestion, congestion, str_len(congestion));

        switch (gt_setup_crypto(&ctx, sock.fd, listener)) {
        case -2:
            gt_log("%s: key exchange could not be verified!\n", sockname);
            goto restart;
        case -1:
            gt_log("%s: key exchange failed\n", sockname);
            goto restart;
        default:
            break;
        }

        retry = 0;

        gt_log("%s: running\n", sockname);

        fd_set rfds;
        FD_ZERO(&rfds);

        int stop_loop = 0;

        buffer_format(&sock.write);
        buffer_format(&sock.read);

        while (1) {
            if _0_(gt_close)
                stop_loop |= 1;

            if _0_(stop_loop) {
                if (((stop_loop&(1<<2)) || !buffer_read_size(&sock.write)) &&
                    ((stop_loop&(1<<1)) || !buffer_read_size(&sock.read)))
                    goto restart;
                FD_CLR(tun.fd, &rfds);
            } else {
                if (!blks[blk_write].size) {
                    FD_SET(tun.fd, &rfds);
                } else {
                    FD_CLR(tun.fd, &rfds);
                }
            }

            buffer_shift(&sock.read);

            if (buffer_write_size(&sock.read)) {
                FD_SET(sock.fd, &rfds);
            } else {
                FD_CLR(sock.fd, &rfds);
            }

            struct timeval timeout = {
                .tv_usec = 1000,
            };

            if _0_(select(sock.fd+1, &rfds, NULL, NULL, &timeout)==-1) {
                if (errno==EINTR)
                    continue;
                perror("select");
                return 1;
            }

         // TODO
         // struct timeval now;
         // gettimeofday(&now, NULL);

            if (FD_ISSET(tun.fd, &rfds)) {
                while (!blks[blk_write].size) {
                    uint8_t *data = blks[blk_write].data;
                    const ssize_t r = tun_read(tun.fd, data, GT_MTU_MAX);

                    if (r<=0) {
                        gt_close |= !r;
                        break;
                    }

                    const ssize_t ip_size = ip_get_size(data, GT_MTU_MAX);

                    if _0_(ip_size<=0)
                        continue;

                    if _0_(ip_size!=r) {
                        uint8_t tmp[2*GT_MTU_MAX+1];
                        gt_dump(tmp, sizeof(tmp), data, GT_MTU_MAX);
                        gt_log("%s: DUMP %zi %s\n", sockname, r, tmp);
                        continue;
                    }

                    if _0_(debug)
                        gt_print_hdr(data, ip_size, sockname);


                    blks[blk_write++].size = r;
                    blk_count++;
                }
            }

            while (1) {
                buffer_shift(&tun.read);

                if _0_(!stop_loop) {
                    for (; blk_count; blk_read++) {
                        const size_t size = blks[blk_read].size;

                        if (!size || buffer_write_size(&tun.read)<size)
                            break;

                        byte_cpy(tun.read.write, blks[blk_read].data, size);
                        tun.read.write += size;

                        blks[blk_read].size = 0;
                        blk_count--;
                    }

                    gt_encrypt(&ctx, &sock.write, &tun.read);
                }

                if (!buffer_read_size(&sock.write))
                    break;

                const ssize_t r = fd_write(sock.fd, sock.write.read,
                                           buffer_read_size(&sock.write));

                if (r>0) {
                    sock.write.read += r;
                } else {
                    if (!r)
                        stop_loop |= (1<<2);
                    break;
                }
            }

            if _0_(stop_loop && !buffer_read_size(&sock.write)) {
                if (!(stop_loop&(1<<2))) {
                    stop_loop |= (1<<2);
                    shutdown(sock.fd, SHUT_WR);
                    gt_log("%s: shutdown\n", sockname);
                }
            }

            buffer_shift(&sock.write);

            if (FD_ISSET(sock.fd, &rfds)) {
                if (noquickack)
                    sk_set_int(sock.fd, sk_quickack, 0);

                const ssize_t r = fd_read(sock.fd, sock.read.write,
                                          buffer_write_size(&sock.read));

                if (r>0) {
                    sock.read.write += r;
                } else if (!r) {
                    stop_loop |= (1<<1);
                }
            }

            while (1) {
                buffer_shift(&tun.write);

                if _0_(gt_decrypt(&ctx, &tun.write, &sock.read)) {
                    gt_log("%s: message could not be verified!\n", sockname);
                    goto restart;
                }

                size_t size = buffer_read_size(&tun.write);
                ssize_t ip_size = ip_get_size(tun.write.read, size);

                if _0_(!ip_size) {
                    gt_log("%s: bad packet!\n", sockname);
                    goto restart;
                }

                if (ip_size<0 || (size_t)ip_size>size)
                    break;

                ssize_t r = tun_write(tun.fd, tun.write.read, ip_size);

                if (r>0) {
                    tun.write.read += r;
                } else {
                    gt_close |= !r;
                    break;
                }
            }
        }

    restart:
        if (sockname) {
            free(sockname);
            sockname = NULL;
        }

        if (sock.fd!=-1) {
            close(sock.fd);
            sock.fd = -1;
        }
    }

    freeaddrinfo(ai);

    free(blks);

    free(sock.write.data);
    free(sock.read.data);

    free(tun.write.data);
    free(tun.read.data);

    return 0;
}
