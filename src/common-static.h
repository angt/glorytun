#pragma once

#include "common.h"

#include <unistd.h>
#include <errno.h>

static inline void byte_set (void *dst, const char value, size_t size)
{
    if (!dst)
        return;

    char *restrict d = dst;

    while (size--)
        *d++ = value;
}

static inline void byte_cpy (void *dst, const void *src, size_t size)
{
    if (!dst || !src)
        return;

    char *restrict d = dst;
    const char *restrict s = src;

    while (size--)
        *d++ = *s++;
}

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

static inline int str_cmp (const char *restrict sa, const char *restrict sb)
{
    if (!sa || !sb)
        return 1;

     while (*sa==*sb++)
         if (!*sa++)
             return 0;

    return 1;
}

static inline size_t str_len (const char *restrict str)
{
    if (!str)
        return 0;

    size_t i = 0;

    while (str[i])
        i++;

    return i;
}

static inline char *str_cat (const char *const strs[], size_t count)
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
        byte_cpy(p, strs[i], len);
        p += len;
    }

    p[0] = 0;

    return str;
}

static inline void buffer_setup (buffer_t *buffer, void *data, size_t size)
{
    if (!data)
        data = malloc(ALIGN(size));

    buffer->data  = data;
    buffer->read  = data;
    buffer->write = data;
    buffer->end   = data;
    buffer->end  += size;
}

static inline void buffer_format (buffer_t *buffer)
{
    buffer->write = buffer->data;
    buffer->read  = buffer->data;
}

static inline size_t buffer_size (buffer_t *buffer)
{
    return buffer->end-buffer->data;
}

static inline size_t buffer_write_size (buffer_t *buffer)
{
    return buffer->end-buffer->write;
}

static inline size_t buffer_read_size (buffer_t *buffer)
{
    return buffer->write-buffer->read;
}

static inline void buffer_shift (buffer_t *buffer)
{
    if (buffer->read==buffer->write) {
        buffer_format(buffer);
    } else {
        const uint8_t *src = PALIGN_DOWN(buffer->read);
        const size_t size = ALIGN(buffer->write-src);
        if (buffer->data+size<src) {
            byte_cpy(buffer->data, src, size);
            buffer->read  -= src-buffer->data;
            buffer->write -= src-buffer->data;
        }
    }
}
