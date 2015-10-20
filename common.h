#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <errno.h>

#define COUNT(x) (sizeof(x)/sizeof(x[0]))

static inline size_t str_cpy (char *dst, char *src, size_t n)
{
    if (!dst || !src)
        return 0;

    size_t i;

    for (i=0; i<n && src[i]; i++)
        dst[i] = src[i];

    dst[i] = 0;

    return i;
}
