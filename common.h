#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#define COUNT(x) (sizeof(x)/sizeof(x[0]))

#define ALIGN_SIZE     (1<<4)
#define ALIGN_MASK     (ALIGN_SIZE-1)

#define ALIGN(x)       (((x)+ALIGN_MASK)&~ALIGN_MASK)
#define ALIGN_DOWN(x)  ((x)&~ALIGN_MASK)

#define PALIGN(x)      ((void *)ALIGN((size_t)(x)))
#define PALIGN_DOWN(x) ((void *)ALIGN_DOWN((size_t)(x)))

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

typedef struct buffer buffer_t;

struct buffer {
    uint8_t *data;
    uint8_t *read;
    uint8_t *write;
    uint8_t *end;
};

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
