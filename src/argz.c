#include "argz.h"
#include "common.h"
#include "ctl.h"

void
gt_set_port(union mud_sockaddr *s, uint16_t port)
{
    switch (s->sa.sa_family) {
        case AF_INET:    s->sin.sin_port = htons(port); break;
        case AF_INET6: s->sin6.sin6_port = htons(port); break;
    }
}

uint16_t
gt_get_port(union mud_sockaddr *s)
{
    switch (s->sa.sa_family) {
        case AF_INET:  return ntohs(s->sin.sin_port);
        case AF_INET6: return ntohs(s->sin6.sin6_port);
    }
    return 0;
}

int
gt_toaddr(char *str, size_t size, union mud_sockaddr *s)
{
    memset(str, 0, size);

    switch (s->sa.sa_family) {
        case AF_INET:  inet_ntop(AF_INET,  &s->sin.sin_addr,   str, size); break;
        case AF_INET6: inet_ntop(AF_INET6, &s->sin6.sin6_addr, str, size); break;
        default: return 1;
    }
    return 0;
}

int
gt_totime(char *str, size_t size, unsigned long long t)
{
    if (!str || size < 4) {
        errno = EINVAL;
        return -1;
    }
    if (!t) {
        memcpy(str, "now", 4);
        return 0;
    }
    struct {
        unsigned long long v;
        unsigned long long n;
        char *name;
    } u[] = {
        {0, 1000, "ms"},
        {0,   60,  "s"},
        {0,   60,  "m"},
        {0,   24,  "h"},
        {0,    0,  "d"},
    };
    size_t len = 0;
    unsigned i = 0;

    while (u[i].n) {
        u[i].v = t % u[i].n;
        t /= u[i].n;
        i++;
    }
    u[i++].v = t;

    while (i--) if (u[i].v) {
        int ret = snprintf(str + len, size - len,
                           "%llu%s", u[i].v, u[i].name);

        if (ret <= 0 || (size_t)ret >= size - len) {
            errno = EINVAL;
            return -1;
        }
        len += ret;
    }
    return 0;
}

int
gt_torate(char *str, size_t size, unsigned long long r)
{
    if (!str || size < 5) {
        errno = EINVAL;
        return -1;
    }
    unsigned k = 0;

    while (r && k < 4 && !(r % 1000)) {
        r /= 1000; k++;
    }
    int ret = snprintf(str, size, "%llu%sbit%s", r,
                       &"\0\0k\0M\0G\0T"[k << 1],
                       &"s"[r <= 1]);

    if (ret <= 0 || (size_t)ret >= size) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

void
gt_argz_print(const char *str)
{
    printf("%s\n", str);
}

int
gt_argz_percent_suffix(struct argz_ull *ull, const char *s)
{
    return s && s[0] && strcmp(s, "%");
}

int
gt_argz_dev(int argc, char **argv, void *data)
{
    if (argz_help_me(argc, argv)) {
        ctl_foreach(gt_argz_print);
    } else if (argc > 1) {
        memcpy(data, &argv[1], sizeof(char *));
        return argc - 2;
    } else {
        gt_log("Option %s requires a tunnel device\n", argv[0]);
    }
    return -1;
}

int
gt_argz_addr_ip(int argc, char **argv, void *data)
{
    struct gt_argz_addr *addr = (struct gt_argz_addr *)data;

    if (argz_help_me(argc, argv)) {
        char tmp[INET6_ADDRSTRLEN];
        if (!gt_toaddr(tmp, sizeof(tmp), &addr->sock))
            printf("%s\n", tmp);
    } else if (argc > 1) {
        if (inet_pton(AF_INET, argv[1], &addr->sock.sin.sin_addr) == 1) {
            addr->sock.sa.sa_family = AF_INET;
        } else if (inet_pton(AF_INET6, argv[1], &addr->sock.sin6.sin6_addr) == 1) {
            addr->sock.sa.sa_family = AF_INET6;
        } else {
            gt_log("Option %s is not a valid IP address\n", argv[1]);
            return -1;
        }
        return argc - 2;
    } else {
        gt_log("Option %s requires an IP address\n", argv[0]);
    }
    return -1;
}

int
gt_argz_addr(int argc, char **argv, void *data)
{
    struct gt_argz_addr *addr = (struct gt_argz_addr *)data;

    struct argz_ull port = {
        .value = gt_get_port(&addr->sock),
        .min = 0,
        .max = 0xFFFF,
    };
    struct argz z[] = {
        {"addr", "IP address", gt_argz_addr_ip,  data},
        {"port", "Port number",       argz_ull, &port},
        {0}};

    int ret = argz(argc, argv, z);
    gt_set_port(&addr->sock, port.value);
    return ret;
}
