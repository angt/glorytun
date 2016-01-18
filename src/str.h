#pragma once

#include "common.h"

static inline size_t str_cpy (char *restrict dst, const char *restrict src, size_t len)
{
    if (!dst || !src)
        return 0;

    size_t i;

    for (i=0; i<len && src[i]; i++)
        dst[i] = src[i];

    dst[i] = 0;

    return i;
}

_pure_
static inline int str_empty (const char *restrict str)
{
    return !str || !str[0];
}

_pure_
static inline size_t str_cmp (const char *restrict sa, const char *restrict sb)
{
    if (!sa || !sb)
        return 1;

    size_t i = 0;

    while (sa[i]==sb[i])
        if (!sa[i++])
            return 0;

    return i+1;
}

_pure_
static inline size_t str_len (const char *restrict str)
{
    if (!str)
        return 0;

    return strlen(str);
}

static inline char *str_cat (const char **strs, size_t count)
{
    size_t size = 1;

    for (size_t i=0; i<count; i++)
        size += str_len(strs[i]);

    char *str = malloc(size);

    if (!str)
        return NULL;

    char *p = str;

    for (size_t i=0; i<count; i++) {
        size_t len = str_len(strs[i]);
        memcpy(p, strs[i], len);
        p += len;
    }

    p[0] = 0;

    return str;
}
