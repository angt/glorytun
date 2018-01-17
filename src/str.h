#pragma once

#include "common.h"

_pure_ static inline int
str_empty(const char *restrict str)
{
    return !str || !str[0];
}

_pure_ static inline size_t
str_cmp(const char *restrict sa, const char *restrict sb)
{
    if (!sa || !sb)
        return 1;

    size_t i = 0;

    while (sa[i] == sb[i])
        if (!sa[i++])
            return 0;

    return i + 1;
}

_pure_ static inline size_t
str_len(const char *restrict str)
{
    if (!str)
        return 0;

    return strlen(str);
}

static inline size_t
str_cat(char *dst, const char **src, size_t count, size_t dst_len)
{
    if (count && !src)
        return 0;

    size_t len = 0;
    size_t p = 0;

    for (size_t i = 0; i < count; i++) {
        size_t n = str_len(src[i]);

        if (!n)
            continue;

        if (dst && len + n <= dst_len) {
            memmove(&dst[len], src[i], n);
            p = len + n;
        }

        len += n;
    }

    if (dst)
        dst[p] = 0;

    return len;
}

static inline size_t
str_cpy(char *dst, const char *src, size_t dst_len)
{
    return str_cat(dst, &src, 1, dst_len);
}
