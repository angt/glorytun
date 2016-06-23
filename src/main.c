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
#include <time.h>
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

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define GT_MTU_MAX   (1500)
#define GT_PKT_MAX   (32*1024)
#define GT_TUNR_SIZE (GT_PKT_MAX-16-2)
#define GT_TUNW_SIZE (GT_PKT_MAX)

#define GT_ABYTES    (16)
#define GT_KEYBYTES  (32)

#define MPTCP_ENABLED (26)

static struct {
    volatile sig_atomic_t quit;
    volatile sig_atomic_t info;
    long timeout;
    int mptcp;
    int state_fd;
} gt;

struct fdbuf {
    int fd;
    buffer_t read;
    buffer_t write;
};

struct crypto_ctx {
    struct {
        uint8_t key[512] _align_(16);
        uint8_t nonce[16];
    } write, read;
    uint8_t skey[crypto_generichash_KEYBYTES];
    int chacha;
};

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
    sk_user_timeout,
    sk_mptcp,
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
        [sk_user_timeout] = { "TCP_USER_TIMEOUT",
#ifdef TCP_USER_TIMEOUT
            1, IPPROTO_TCP, TCP_USER_TIMEOUT,
#endif
        },
        [sk_mptcp] = { "MPTCP_ENABLED",
#ifdef MPTCP_ENABLED
            1, IPPROTO_TCP, MPTCP_ENABLED,
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

    if (gt.mptcp)
        sk_set_int(fd, sk_mptcp, 1);

    if (bind(fd, ai->ai_addr, ai->ai_addrlen)==-1) {
        perror("bind");
        return -1;
    }

    if (listen(fd, 8)==-1) {
        perror("listen");
        return -1;
    }

#ifdef __linux__
    sk_set_int(fd, sk_defer_accept, gt.timeout/1000);
#else
    char data[256] = "dataready";
    sk_set(fd, sk_acceptfilter, &data, sizeof(data));
#endif

    return 0;
}

static int sk_connect (int fd, struct addrinfo *ai)
{
    fd_set_nonblock(fd);

    if (gt.mptcp)
        sk_set_int(fd, sk_mptcp, 1);

    int ret = connect(fd, ai->ai_addr, ai->ai_addrlen);

    if (ret==-1) {
        if (errno==EINTR)
            return 0;

        if (errno==EINPROGRESS) {
            struct pollfd pollfd = {
                .fd = fd,
                .events = POLLOUT,
            };

            if (!poll(&pollfd, 1, gt.timeout))
                return -1;

            int opt = 0;
            socklen_t optlen = sizeof(opt);

            getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt, &optlen);

            if (!opt)
                return 0;

            errno = opt;
        }
    }

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

    if (ret==-1) {
        if (errno!=EINTR)
            perror("accept");
        return -1;
    }

    fd_set_nonblock(ret);

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

    const char *strs[] = {
        host, ".", port
    };

    return str_cat(strs, COUNT(strs));
}

static struct addrinfo *ai_create (const char *host, const char *port, int listener)
{
    if (str_empty(port)) {
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

static int gt_encrypt (struct crypto_ctx *ctx, buffer_t *dst, buffer_t *src)
{
    const size_t rs = buffer_read_size(src);
    const size_t ws = buffer_write_size(dst);

    if (!rs || !ws)
        return 0;

    const size_t size = rs+GT_ABYTES;

    if (size+2>ws)
        return 0;

    dst->write[0] = 0xFF&(size>>8);
    dst->write[1] = 0xFF&(size);

    if (ctx->chacha) {
        crypto_aead_chacha20poly1305_encrypt(
                dst->write+2, NULL,
                src->read, rs,
                dst->write, 2,
                NULL, ctx->write.nonce,
                ctx->write.key);

        sodium_increment(ctx->write.nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
    } else {
        crypto_aead_aes256gcm_encrypt_afternm(
                dst->write+2, NULL,
                src->read, rs,
                dst->write, 2,
                NULL, ctx->write.nonce,
                (const crypto_aead_aes256gcm_state *)ctx->write.key);

        sodium_increment(ctx->write.nonce, crypto_aead_aes256gcm_NPUBBYTES);
    }

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

    if (rs<=2+GT_ABYTES)
        return 0;

    const size_t size = (src->read[0]<<8)|src->read[1];

    if (size-GT_ABYTES>ws)
        return 0;

    if (size+2>rs)
        return 0;

    if (ctx->chacha) {
        if (crypto_aead_chacha20poly1305_decrypt(
                    dst->write, NULL,
                    NULL,
                    src->read+2, size,
                    src->read, 2,
                    ctx->read.nonce,
                    ctx->read.key))
            return -1;

        sodium_increment(ctx->read.nonce, crypto_aead_chacha20poly1305_NPUBBYTES);
    } else {
        if (crypto_aead_aes256gcm_decrypt_afternm(
                    dst->write, NULL,
                    NULL,
                    src->read+2, size,
                    src->read, 2,
                    ctx->read.nonce,
                    (const crypto_aead_aes256gcm_state *)ctx->read.key))
            return -1;

        sodium_increment(ctx->read.nonce, crypto_aead_aes256gcm_NPUBBYTES);
    }

    src->read += size+2;
    dst->write += size-GT_ABYTES;

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

struct seq_elem {
    uint32_t seq;
    uint32_t size;
};

struct seq_array {
    struct seq_elem *elem;
    uint32_t count;
    uint32_t base;
};

struct tcp_entry {
    uint8_t key[37];
    struct {
        struct seq_array sa;
        size_t retrans;
    } data[2];
};

void tcp_entry_free (struct tcp_entry *te)
{
    free(te->data[0].sa.elem);
    free(te->data[1].sa.elem);
    free(te);
}

void sa_insert_elem (struct seq_array *sa, uint32_t i, uint32_t seq, uint32_t size)
{
    if (sa->count<i)
        return;

    if (!(sa->count&7)) {
        struct seq_elem *tmp = realloc(sa->elem, (sa->count+8)*sizeof(struct seq_elem));

        if (!tmp) {
            gt_log("couldn't realloc!\n");
            return;
        }

        sa->elem = tmp;
    }

    memmove(&sa->elem[i+1], &sa->elem[i], (sa->count-i)*sizeof(struct seq_elem));

    sa->elem[i].seq = seq;
    sa->elem[i].size = size;
    sa->count++;
}

void sa_remove_elem (struct seq_array *sa, uint32_t i)
{
    if (sa->count<i+1)
        return;

    sa->count--;

    memmove(&sa->elem[i], &sa->elem[i+1], (sa->count-i)*sizeof(struct seq_elem));
}

int sa_have (struct seq_array *sa, uint32_t seq, uint32_t size)
{
    uint32_t i;
    uint32_t seqa = seq-sa->base;

    for (i=0; i<sa->count; i++) {
        uint32_t seqb = sa->elem[i].seq-sa->base;

        if (seqb>=seqa) {
            uint32_t d = seqb-seqa;

            if (d>size)
                return 0;
        } else {
            uint32_t d = seqa-seqb;

            if (d>=sa->elem[i].size)
                continue;

            if (d+size>sa->elem[i].size) {
                gt_print("sa_have:part\n");
                return 0; // XXX 0
            }
        }

        return 1;
    }

    return 0;
}

void sa_rebase (struct seq_array *sa, uint32_t seq)
{
    if (!sa->count)
        return;

    if (seq==sa->base)
        return;

    uint32_t size = seq-sa->elem[0].seq;

    if (size==sa->elem[0].size) {
        sa_remove_elem(sa, 0);
    } else {
        if (size>sa->elem[0].size)
            return;
        sa->elem[0].seq = seq;
        sa->elem[0].size -= size;
    }

    sa->base = seq;
}

void sa_insert (struct seq_array *sa, uint32_t seq, uint32_t size)
{
    uint32_t i;
    uint32_t seqa = seq-sa->base;

    for (i=0; i<sa->count; i++) {
        uint32_t seqb = sa->elem[i].seq-sa->base;

        if (seqb>=seqa) {
            uint32_t d = seqb-seqa;

            if (d>size)
                break;

            sa->elem[i].seq = seq;

            uint32_t new_size = sa->elem[i].size+d;

            if (new_size>size) {
                sa->elem[i].size = new_size;
            } else {
                sa->elem[i].size = size;
            }
        } else {
            uint32_t d = seqa-seqb;

            if (d>sa->elem[i].size)
                continue;

            uint32_t new_size = size+d;

            if (new_size>sa->elem[i].size)
                sa->elem[i].size = new_size;
        }

        if (i+1<sa->count) {
            if (seqb+sa->elem[i].size==sa->elem[i+1].seq-sa->base) {
                sa->elem[i].size += sa->elem[i+1].size;
                sa_remove_elem(sa, i+1);
            }
        }

        return;
    }

    sa_insert_elem(sa, i, seq, size);
}

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

static void gt_print_entry (struct tcp_entry *te)
{
    uint8_t *key = &te->key[1];
    size_t size = te->key[0];

    char ip0[INET6_ADDRSTRLEN] = {0};
    char ip1[INET6_ADDRSTRLEN] = {0};

    uint16_t port0 = 0;
    uint16_t port1 = 0;

    switch (size) {
    case 8+4:
        inet_ntop(AF_INET, key, ip0, sizeof(ip0));
        inet_ntop(AF_INET, key+4, ip1, sizeof(ip1));
        port0 = (key[8]<<8)|key[9];
        port1 = (key[10]<<8)|key[11];
        break;
    case 32+4:
        inet_ntop(AF_INET6, key,  ip0, sizeof(ip0));
        inet_ntop(AF_INET6, key+16, ip1, sizeof(ip1));
        port0 = (key[32]<<8)|key[33];
        port1 = (key[34]<<8)|key[35];
        break;
    }

    gt_print("connection:%s.%hu-%s.%hu\t"
             "retrans:%zu, %zu\n",
             ip0, port0, ip1, port1,
             te->data[0].retrans,
             te->data[1].retrans);
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

    if (tcp.th_flags&(TH_FIN|TH_RST)) {
        if (r_entry) {
            gt_print_entry(r_entry);
            db_remove(db, entry.key);
            tcp_entry_free(r_entry);
        }
        return 0;
    }

    if (tcp.th_flags&TH_ACK) {
        if (!r_entry) {
            r_entry = calloc(1, sizeof(entry));

            if (!r_entry)
                return 0;

            memcpy(r_entry->key, entry.key, sizeof(entry.key));

            if (!db_insert(db, r_entry->key)) {
                free(r_entry);
                return 0;
            }

            gt_print_entry(r_entry);

            r_entry->data[1-rev].sa.base = tcp.th_ack;
            r_entry->data[rev].sa.base = tcp.th_seq;
        } else {
            sa_rebase(&r_entry->data[1-rev].sa, tcp.th_ack);
        }
    }

    if (!r_entry)
        return 0;

    uint32_t size = ic->size-ic->hdr_size-tcp.th_off*4;

    if (!size)
        return 0;

    if (sa_have(&r_entry->data[rev].sa, tcp.th_seq, size)) {
        r_entry->data[rev].retrans++;
    } else {
        sa_insert(&r_entry->data[rev].sa, tcp.th_seq, size);
    }

    return 0;
}

static unsigned long long gt_now (void)
{
#if defined __APPLE__
    static mach_timebase_info_data_t mtid;
    if (!mtid.denom) mach_timebase_info(&mtid);
    return (mach_absolute_time()*mtid.numer/mtid.denom)/1000ULL;
#elif defined CLOCK_MONOTONIC
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return tv.tv_sec*1000000ULL+tv.tv_nsec/1000ULL;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec*1000000ULL+tv.tv_usec;
#endif
}

static void gt_bench (int chacha)
{
    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES];
    memset(npub, 0, sizeof(npub));

    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    memset(key, 1, sizeof(key));

    crypto_aead_aes256gcm_state ctx;

    if (!chacha)
        crypto_aead_aes256gcm_beforenm(&ctx, key);

    gt_print("bench: %s\n", chacha?"chacha20poly1305":"aes256gcm");

    _align_(16) unsigned char buf[32*1024+crypto_aead_aes256gcm_ABYTES];

    size_t bs = 8;

    while (!gt.quit && bs<=sizeof(buf)) {
        size_t total_size = 0;
        unsigned long long total_dt = 0.0;
        double mbps = 0.0;

        while (!gt.quit) {
            unsigned long long now = gt_now();

            size_t size = 0;

            while (!gt.quit && size<16*1024*1024) {
                if (chacha) {
                    crypto_aead_chacha20poly1305_encrypt(buf, NULL,
                            buf, bs, NULL, 0, NULL, npub, key);
                } else {
                    crypto_aead_aes256gcm_encrypt_afternm(buf, NULL,
                            buf, bs, NULL, 0, NULL, npub,
                            (const crypto_aead_aes256gcm_state *)&ctx);
                }
                size += bs;
            }

            total_dt += gt_now()-now;
            total_size += size;

            double last_mbps = mbps;
            mbps = total_size*8.0/total_dt;

            double diff = mbps-last_mbps;

            if (-0.1<diff && diff<0.1)
                break;
        }

        gt_print("%6zu bytes %9.2f Mbps\n", bs, mbps);
        bs *= 2;
    }
}

static int gt_setup_secretkey (struct crypto_ctx *ctx, char *keyfile)
{
    const size_t size = sizeof(ctx->skey);

    if (str_empty(keyfile)) {
        char buf[2*size+1];

        randombytes_buf(ctx->skey, size);
        gt_tohex(buf, sizeof(buf), ctx->skey, size);
        state_send(gt.state_fd, "SECRETKEY", buf);

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
    const uint8_t proto[] = {'G', 'T', VERSION_MAJOR, (uint8_t)ctx->chacha };

    const size_t size = 96;
    const size_t hash_size = 32;

    uint8_t secret[crypto_scalarmult_SCALARBYTES];
    uint8_t shared[crypto_scalarmult_BYTES];

    uint8_t key_r[GT_KEYBYTES];
    uint8_t key_w[GT_KEYBYTES];

    uint8_t data_r[size], data_w[size];
    uint8_t auth_r[hash_size], auth_w[hash_size];
    uint8_t hash[hash_size];

    crypto_generichash_state state;

    memset(data_w, 0, size);

    randombytes_buf(secret, sizeof(secret));
    crypto_scalarmult_base(data_w, secret);

    memcpy(&data_w[size-hash_size-sizeof(proto)], proto, sizeof(proto));

    crypto_generichash(&data_w[size-hash_size], hash_size,
            data_w, size-hash_size, ctx->skey, sizeof(ctx->skey));

    if (!listener && fd_write_all(fd, data_w, size)!=size)
        return -1;

    if (fd_read_all(fd, data_r, size)!=size)
        return -1;

    if (memcmp(&data_r[size-hash_size-sizeof(proto)], proto, 3)) {
        gt_log("bad packet [%02X%02X%02X] !\n",
            &data_r[size-hash_size-sizeof(proto)+0],
            &data_r[size-hash_size-sizeof(proto)+1],
            &data_r[size-hash_size-sizeof(proto)+2]);
        return -2;
    }

    if (data_r[size-hash_size-sizeof(proto)+3] && !ctx->chacha) {
        gt_log("peer wants chacha20\n");
        ctx->chacha = 1;
    }

    crypto_generichash(hash, hash_size,
            data_r, size-hash_size, ctx->skey, sizeof(ctx->skey));

    if (sodium_memcmp(&data_r[size-hash_size], hash, hash_size)) {
        gt_log("peer sends a bad hash!\n");
        return -2;
    }

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

    if (sodium_memcmp(auth_r, hash, hash_size)) {
        gt_log("peer sends a bad hash (challenge-response)!\n");
        return -2;
    }

    if (crypto_scalarmult(shared, secret, data_r)) {
        gt_log("I'm just gonna hurt you really, really, BAD\n");
        return -2;
    }

    crypto_generichash_init(&state, ctx->skey, sizeof(ctx->skey), sizeof(key_r));
    crypto_generichash_update(&state, shared, sizeof(shared));
    crypto_generichash_update(&state, data_r, size);
    crypto_generichash_update(&state, data_w, size);
    crypto_generichash_final(&state, key_r, sizeof(key_r));

    crypto_generichash_init(&state, ctx->skey, sizeof(ctx->skey), sizeof(key_w));
    crypto_generichash_update(&state, shared, sizeof(shared));
    crypto_generichash_update(&state, data_w, size);
    crypto_generichash_update(&state, data_r, size);
    crypto_generichash_final(&state, key_w, sizeof(key_w));

    if (ctx->chacha) {
        memcpy(ctx->read.key, key_r, sizeof(key_r));
        memcpy(ctx->write.key, key_w, sizeof(key_w));
    } else {
        crypto_aead_aes256gcm_beforenm(&ctx->read.key, key_r);
        crypto_aead_aes256gcm_beforenm(&ctx->write.key, key_w);
    }

    sodium_memzero(secret, sizeof(secret));
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(key_r, sizeof(key_r));
    sodium_memzero(key_w, sizeof(key_w));

    memset(ctx->read.nonce, 0, sizeof(ctx->read.nonce));
    memset(ctx->write.nonce, 0, sizeof(ctx->write.nonce));

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

    long buffer_size = GT_PKT_MAX;

    long ka_count = -1;
    long ka_idle = -1;
    long ka_interval = -1;

    long retry_count = -1;
    long retry_slope = 0;
    long retry_const = 0;
    long retry_limit = 1000000;

    gt.timeout = 5000;

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
        { "listener",    NULL,          option_option },
        { "host",        &host,         option_str    },
        { "port",        &port,         option_str    },
        { "dev",         &dev,          option_str    },
        { "keyfile",     &keyfile,      option_str    },
        { "congestion",  &congestion,   option_str    },
        { "delay",       NULL,          option_option },
        { "multiqueue",  NULL,          option_option },
        { "keepalive",   ka_opts,       option_option },
        { "buffer-size", &buffer_size,  option_long   },
        { "noquickack",  NULL,          option_option },
        { "retry",       &retry_opts,   option_option },
        { "statefile",   &statefile,    option_str    },
        { "timeout",     &gt.timeout,   option_long   },
        { "bench",       NULL,          option_option },
        { "chacha20",    NULL,          option_option },
        { "mptcp",       NULL,          option_option },
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

    const int listener = option_is_set(opts, "listener");
    const int delay = option_is_set(opts, "delay");
    const int keepalive = option_is_set(opts, "keepalive");
    const int noquickack = option_is_set(opts, "noquickack");
    const int debug = option_is_set(opts, "debug");

    int chacha = option_is_set(opts, "chacha20");

    gt.mptcp = option_is_set(opts, "mptcp");

    if (sodium_init()==-1) {
        gt_log("libsodium initialization has failed\n");
        return 1;
    }

    if (!chacha && !crypto_aead_aes256gcm_is_available()) {
        gt_na("AES-256-GCM");
        chacha = 1;
    }

    if (option_is_set(opts, "bench")) {
        gt_bench(chacha);
        return 0;
    }

    if (buffer_size < GT_PKT_MAX) {
        buffer_size = GT_PKT_MAX;
        gt_log("buffer size must be greater than or equal to %li\n", buffer_size);
    }

    if (!listener) {
        if (!option_is_set(opts, "keyfile")) {
            gt_log("keyfile option must be set\n");
            return 1;
        }

        if (!option_is_set(opts, "retry"))
            retry_count = 0;
    }

    if (gt.timeout<=0 || gt.timeout>INT_MAX) {
        gt_log("bad timeout\n");
        return 1;
    }

    struct addrinfo *ai = ai_create(host, port, listener);

    if (!ai)
        return 1;

    gt.state_fd = state_create(statefile);

    if (statefile && gt.state_fd==-1)
        return 1;

    struct fdbuf tun  = { .fd = -1 };
    struct fdbuf sock = { .fd = -1 };

    char *tun_name = NULL;

    tun.fd = tun_create(dev, &tun_name, option_is_set(opts, "multiqueue"));

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

    long retry = 0;
    uint8_t *db = NULL;

    state_send(gt.state_fd, "INITIALIZED", tun_name);

    while (!gt.quit) {
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

        if (str_empty(sockname)) {
            close(sock.fd);
            continue;
        }

        gt_log("%s: connected\n", sockname);

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

        sk_set_int(sock.fd, sk_user_timeout, gt.timeout);
        sk_set(sock.fd, sk_congestion, congestion, str_len(congestion));

        ctx.chacha = chacha;

        if (gt_setup_crypto(&ctx, sock.fd, listener)) {
            gt_log("%s: key exchange failed\n", sockname);
            goto restart;
        }

        retry = 0;

        state_send(gt.state_fd, "STARTED", tun_name);

        fd_set rfds;
        FD_ZERO(&rfds);

        int stop_loop = 0;

        buffer_format(&sock.write);
        buffer_format(&sock.read);

        while (1) {
            if _0_(gt.quit)
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
                .tv_usec = 100000,
            };

            if (buffer_read_size(&sock.write))
                timeout.tv_usec = 1000;

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
                        gt.quit |= !r;
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
                        if (gt_track(&db, &ic, tun.read.write, 0))
                            continue;
                    }

                    tun.read.write += r;
                }
            }

            buffer_shift(&sock.write);

            if _1_(!stop_loop)
                gt_encrypt(&ctx, &sock.write, &tun.read);

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

            buffer_shift(&tun.write);

            if _0_(gt_decrypt(&ctx, &tun.write, &sock.read)) {
                gt_log("%s: message could not be verified!\n", sockname);
                goto restart;
            }

            while (1) {
                size_t size = buffer_read_size(&tun.write);

                if (!size)
                    break;

                struct ip_common ic;

                if (ip_get_common(&ic, tun.write.read, size) || ic.size>size) {
                    gt_log("%s: bad packet!\n", sockname);
                    goto restart;
                }

                if _0_(debug) {
                    if (gt_track(&db, &ic, tun.write.read, 1)) {
                        tun.write.read += ic.size;
                        continue;
                    }
                }

                ssize_t r = tun_write(tun.fd, tun.write.read, ic.size);

                if (r>0) {
                    if (r==ic.size)
                        tun.write.read += r;
                } else {
                    gt.quit |= !r;
                    break;
                }
            }
        }

    restart:
        if (sock.fd!=-1) {
            close(sock.fd);
            sock.fd = -1;
        }

        state_send(gt.state_fd, "STOPPED", tun_name);

        if (sockname) {
            free(sockname);
            sockname = NULL;
        }
    }

    freeaddrinfo(ai);

    free(sock.write.data);
    free(sock.read.data);

    free(tun.write.data);
    free(tun.read.data);

    return 0;
}
