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
str_len(const char *restrict str, size_t len)
{
    if (!str)
        return 0;

    return strnlen(str, len);
}
