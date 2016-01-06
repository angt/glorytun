#include "common.h"

#include "buffer.h"
#include "ip.h"
#include "str.h"
#include "option.h"
#include "tun.h"
#include "db.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>

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
    sk_acceptfilter,
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
        [sk_acceptfilter] = { "SO_ACCEPTFILTER",
#ifdef SO_ACCEPTFILTER
            1, SOL_SOCKET, SO_ACCEPTFILTER,
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

    if (bind(fd, ai->ai_addr, ai->ai_addrlen)==-1) {
        perror("bind");
        return -1;
    }

    if (listen(fd, 8)==-1) {
        perror("listen");
        return -1;
    }

#ifdef __linux__
    sk_set_int(fd, sk_defer_accept, GT_TIMEOUT/1000);
#else
    char data[256] = {0};
    str_cpy(data, "dataready", sizeof(data)-1);
    sk_set(fd, sk_acceptfilter, &data, sizeof(data));
#endif

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

static ssize_t fd_write_str (int fd, const char *str)
{
    return fd_write(fd, str, str_len(str));
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

            if (!poll(&pollfd, 1, GT_TIMEOUT))
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

_pure_
static inline uint32_t sum16 (uint32_t sum, const uint8_t *data, const size_t size)
{
    const size_t lim = size&~1u;

    for (size_t i=0; i<lim; i+=2)
        sum += (data[i]<<8)|data[i+1];

    if (size&1)
        sum += data[size-1]<<8;

    return sum;
}

_const_
static inline uint16_t sum16_final (uint32_t sum)
{
    sum = (sum>>16)+(sum&0xFFFF);
    return ~(sum+(sum>>16));
}

struct tcp_entry {
    uint8_t key[37];
    struct {
        uint32_t seq;
        uint32_t ack;
        size_t count;
        struct timeval time;
    } data[2];
};

static int tcp_entry_set_key (struct tcp_entry *te, struct ip_common *ic, uint8_t *data)
{
    uint8_t *key = &te->key[1];
    size_t size = 0;

    switch (ic->version) {
    case 4:
        size = 8;
        memcpy(key, &data[12], 8);
        break;
    case 6:
        size = 32;
        memcpy(key, &data[9], 32);
        break;
    }

    memcpy(&key[size], &data[ic->hdr_size], 4);
    te->key[0] = size+4;

    return 0;
}

static int tcp_entry_set_key_rev (struct tcp_entry *te, struct ip_common *ic, uint8_t *data)
{
    uint8_t *key = &te->key[1];
    size_t size = 0;

    switch (ic->version) {
    case 4:
        size = 8;
        memcpy(key, &data[12+4], 4);
        memcpy(key+4, &data[12], 4);
        break;
    case 6:
        size = 32;
        memcpy(key, &data[9+16], 16);
        memcpy(key+16, &data[9], 16);
        break;
    }

    memcpy(&key[size], &data[ic->hdr_size+2], 2);
    memcpy(&key[size+2], &data[ic->hdr_size], 2);
    te->key[0] = size+4;

    return 0;
}

static int gt_track (uint8_t **db, struct ip_common *ic, uint8_t *data, int rev)
{
    if (ic->proto!=IPPROTO_TCP)
        return 0;

    if (!ic->hdr_size)
        return 1;

    struct tcp_entry entry;

    if (rev) {
        tcp_entry_set_key_rev(&entry, ic, data);
    } else {
        tcp_entry_set_key(&entry, ic, data);
    }

    struct tcphdr tcp;
    memcpy(&tcp, &data[ic->hdr_size], sizeof(tcp));
    tcp.th_seq = ntohl(tcp.th_seq);
    tcp.th_ack = ntohl(tcp.th_ack);

    struct tcp_entry *r_entry = (void *)db_search(db, entry.key);

    if (!r_entry) {
        r_entry = calloc(1, sizeof(entry));

        if (!r_entry)
            return 1;

        memcpy(r_entry->key, entry.key, sizeof(entry.key));

        if (!db_insert(db, r_entry->key)) {
            free(r_entry);
            return 1;
        }

        gt_print("new tcp entry\n");
    } else {
        gt_print("old_seq:%u\told_ack:%u\tcount:%zu\n",
                r_entry->data[rev].seq,
                r_entry->data[rev].ack,
                r_entry->data[rev].count);
    }

    r_entry->data[rev].seq = tcp.th_seq;
    r_entry->data[rev].ack = tcp.th_ack;
    r_entry->data[rev].count++;
    gettimeofday(&r_entry->data[rev].time, NULL);

    return 0;
}

static void gt_print_hdr (struct ip_common *ic, uint8_t *data)
{
    if (!ic->hdr_size)
        return;

    uint32_t sum = ic->proto+ic->size-ic->hdr_size;

    char ip_src[INET6_ADDRSTRLEN];
    char ip_dst[INET6_ADDRSTRLEN];

    switch (ic->version) {
    case 4:
        inet_ntop(AF_INET, &data[12], ip_src, sizeof(ip_src));
        inet_ntop(AF_INET, &data[16], ip_dst, sizeof(ip_dst));
        sum = sum16(sum, &data[12], 2*4);
        break;
    case 6:
        inet_ntop(AF_INET6, &data[9],  ip_src, sizeof(ip_src));
        inet_ntop(AF_INET6, &data[25], ip_dst, sizeof(ip_dst));
        sum = sum16(sum, &data[9], 2*16); // XXX
        break;
    }

    uint8_t *const packet = &data[ic->hdr_size];

    if (ic->proto==IPPROTO_TCP) {
        struct tcphdr tcp;

        memcpy(&tcp, packet, sizeof(tcp));

        uint16_t tcp_sum = ntohs(tcp.th_sum);
        tcp.th_sum = 0;

        sum = sum16(sum, (uint8_t *)&tcp, sizeof(tcp));
        sum = sum16(sum, &packet[sizeof(tcp)], ic->size-ic->hdr_size-sizeof(tcp));
        uint16_t computed_sum = sum16_final(sum);

        tcp.th_sport = ntohs(tcp.th_sport);
        tcp.th_dport = ntohs(tcp.th_dport);
        tcp.th_seq = ntohl(tcp.th_seq);
        tcp.th_ack = ntohl(tcp.th_ack);
        tcp.th_win = ntohs(tcp.th_win);

        gt_print("proto:%hhu\tsrc:%s.%u\tdst:%s.%u\tseq:%u\tack:%u\twin:%u\tsize:%u\tflags:%c%c%c%c%c%c\tsum:%i\n",
                ic->proto, ip_src, tcp.th_sport, ip_dst, tcp.th_dport,
                tcp.th_seq, tcp.th_ack, tcp.th_win, ic->size-ic->hdr_size-tcp.th_off*4,
                (tcp.th_flags&TH_FIN) ?'F':'.',
                (tcp.th_flags&TH_SYN) ?'S':'.',
                (tcp.th_flags&TH_RST) ?'R':'.',
                (tcp.th_flags&TH_PUSH)?'P':'.',
                (tcp.th_flags&TH_ACK) ?'A':'.',
                (tcp.th_flags&TH_URG) ?'U':'.',
                (computed_sum==tcp_sum));

    } else if (ic->proto==IPPROTO_UDP) {
        struct udphdr udp;

        memcpy(&udp, packet, sizeof(udp));

        udp.uh_sport = ntohs(udp.uh_sport);
        udp.uh_dport = ntohs(udp.uh_dport);
        udp.uh_ulen = ntohs(udp.uh_ulen);

        gt_print("proto:%hhu\tsrc:%s.%u\tdst:%s.%u\tsize:%u\n",
                ic->proto, ip_src, udp.uh_sport, ip_dst, udp.uh_dport, udp.uh_ulen-8);
    } else {
        gt_print("proto:%hhu\tsrc:%s\tdst:%s\tsize:%hu\n",
                ic->proto, ip_src, ip_dst, ic->size);
    }
}

static int gt_setup_secretkey (struct crypto_ctx *ctx, char *keyfile)
{
    const size_t size = sizeof(ctx->skey);

    if (!keyfile) {
        char buf[2*size+1];

        randombytes_buf(ctx->skey, size);
        gt_tohex(buf, sizeof(buf), ctx->skey, size);

        gt_print("new secret key: %s\n", buf);

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

static int gt_setup_crypto (struct crypto_ctx *ctx, int fd, int listener)
{
    const uint8_t gt[] = {'G', 'T', VERSION_MAJOR, 0 };

    const size_t size = 96;
    const size_t hash_size = 32;

    const size_t nonce_size = crypto_aead_aes256gcm_NPUBBYTES;
    const size_t public_size = crypto_scalarmult_SCALARBYTES;

    uint8_t secret[crypto_scalarmult_SCALARBYTES];
    uint8_t shared[crypto_scalarmult_BYTES];
    uint8_t key[crypto_aead_aes256gcm_KEYBYTES];

    uint8_t data_r[size], data_w[size];
    uint8_t auth_r[hash_size], auth_w[hash_size];
    uint8_t hash[hash_size];

    crypto_generichash_state state;

    memset(data_w, 0, size);
    randombytes_buf(data_w, nonce_size);

    randombytes_buf(secret, sizeof(secret));
    crypto_scalarmult_base(&data_w[nonce_size], secret);

    memcpy(&data_w[size-hash_size-sizeof(gt)], gt, sizeof(gt));

    crypto_generichash(&data_w[size-hash_size], hash_size,
            data_w, size-hash_size, ctx->skey, sizeof(ctx->skey));

    if (!listener && fd_write_all(fd, data_w, size)!=size)
        return -1;

    if (fd_read_all(fd, data_r, size)!=size)
        return -1;

    if (memcmp(&data_r[size-hash_size-sizeof(gt)], gt, sizeof(gt)))
        return -2;

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

    memcpy(ctx->read.nonce, data_r, nonce_size);
    memcpy(ctx->write.nonce, data_w, nonce_size);

    return 0;
}

int main (int argc, char **argv)
{
    gt_set_signal();

    char *host = NULL;
    char *port = "5000";
    char *dev = NULL;
    char *keyfile = NULL;
    char *congestion = NULL;
    char *statefile = NULL;

    long buffer_size = GT_BUFFER_SIZE;

    long ka_count = -1;
    long ka_idle = -1;
    long ka_interval = -1;

    long retry_count = -1;
    long retry_slope = 0;
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
        { "statefile",   &statefile,   option_str    },
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
        gt_log("buffer size must be greater than 2048\n");
    }

    if (!listener) {
        if (!option_is_set(opts, "keyfile")) {
            gt_log("keyfile option must be set\n");
            return 1;
        }

        if (!option_is_set(opts, "retry"))
            retry_count = 0;
    }

    if (statefile && statefile[0]!='/') {
        gt_log("statefile must be an absolute path\n");
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

    struct addrinfo *ai = ai_create(host, port, listener);

    if (!ai)
        return 1;

    struct fdbuf tun  = { .fd = -1 };
    struct fdbuf sock = { .fd = -1 };

    tun.fd = tun_create(dev, option_is_set(opts, "multiqueue"));

    if (tun.fd==-1) {
        gt_log("couldn't create tun device\n");
        return 1;
    }

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

    struct crypto_ctx ctx;

    if (gt_setup_secretkey(&ctx, keyfile))
        return 1;

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

    int state_fd = -1;

    if (statefile) {
        state_fd = open(statefile, O_WRONLY);

        if (state_fd==-1) {
            if (errno!=EINTR)
                perror("open statefile");
            return 1;
        }

        struct stat st = {0};

        if (fstat(state_fd, &st)==-1) {
            perror("stat statefile");
            return 1;
        }

        if (!S_ISFIFO(st.st_mode)) {
            gt_log("`%s' is not a fifo\n", statefile);
            return 1;
        }
    }

    long retry = 0;
    uint8_t *db = NULL;

    fd_write_str(state_fd, "INITIALIZED\n");

    while (!gt_close) {
        if (retry_count>=0 && retry>=retry_count+1) {
            gt_log("couldn't %s (%d attempt%s)\n", listener?"listen":"connect",
                   (int)retry, (retry>1)?"s":"");
            break;
        }

        if (retry_slope || retry_const) {
            long usec = retry*retry_slope+retry_const;

            if (usec>retry_limit)
                usec = retry_limit;

            if (usec>0 && usleep(usec)==-1 && errno==EINVAL)
                sleep(usec/1000000);
        }

        if (retry<LONG_MAX)
            retry++;

        sock.fd = listener?sk_accept(fd):sk_create(ai, sk_connect);

        if (sock.fd==-1)
            continue;

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

        fd_write_str(state_fd, "STARTED\n");

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
                buffer_shift(&tun.read);

                if (buffer_write_size(&tun.read)>=GT_MTU_MAX) {
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
                while (1) {
                    const size_t size = buffer_write_size(&tun.read);

                    if (size<GT_MTU_MAX)
                        break;

                    const ssize_t r = tun_read(tun.fd, tun.read.write, GT_MTU_MAX);

                    if (r<=0) {
                        gt_close |= !r;
                        break;
                    }

                    struct ip_common ic;

                    if (ip_get_common(&ic, tun.read.write, GT_MTU_MAX))
                        continue;

                    if _0_(ic.size!=r) {
                        char tmp[2*GT_MTU_MAX+1];
                        gt_tohex(tmp, sizeof(tmp), tun.read.write, r);
                        gt_log("%s: DUMP %zi %s\n", sockname, r, tmp);
                        continue;
                    }

                    if _0_(debug) {
                        gt_print_hdr(&ic, tun.read.write);

                        if (gt_track(&db, &ic, tun.read.write, 0))
                            continue;
                    }

                    tun.read.write += r;
                }

                if _1_(!stop_loop)
                    gt_encrypt(&ctx, &sock.write, &tun.read);
            }

            if (buffer_read_size(&sock.write)) {
                const ssize_t r = fd_write(sock.fd, sock.write.read,
                                           buffer_read_size(&sock.write));

                if (r>0) {
                    sock.write.read += r;
                } else if (!r) {
                    stop_loop |= (1<<2);
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

                if (!size)
                    break;

                struct ip_common ic;

                if (ip_get_common(&ic, tun.write.read, size) || ic.size>size) {
                    gt_log("%s: bad packet!\n", sockname);
                    goto restart;
                }

                if _0_(debug) {
                    gt_print_hdr(&ic, tun.write.read);

                    if (gt_track(&db, &ic, tun.write.read, 1)) {
                        tun.write.read += ic.size;
                        continue;
                    }
                }

                ssize_t r = tun_write(tun.fd, tun.write.read, ic.size);

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

        fd_write_str(state_fd, "STOPPED\n");
    }

    freeaddrinfo(ai);

    free(sock.write.data);
    free(sock.read.data);

    free(tun.write.data);
    free(tun.read.data);

    return 0;
}
