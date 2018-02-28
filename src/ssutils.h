#pragma once

#include <arpa/inet.h>

static inline unsigned short
gt_ss_port(struct sockaddr_storage *ss)
{
    switch (ss->ss_family) {
    case AF_INET:
        return ntohs(((struct sockaddr_in *)ss)->sin_port);
    case AF_INET6:
        return ntohs(((struct sockaddr_in6 *)ss)->sin6_port);
    }

    return 0;
}

static inline int
gt_ss_addr(char *str, size_t size, struct sockaddr_storage *ss)
{
    switch (ss->ss_family) {
    case AF_INET:
        return -!inet_ntop(AF_INET,
                           &((struct sockaddr_in *)ss)->sin_addr, str, size);
    case AF_INET6:
        return -!inet_ntop(AF_INET6,
                           &((struct sockaddr_in6 *)ss)->sin6_addr, str, size);
    }

    return -1;
}
