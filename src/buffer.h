#pragma once

#include "common.h"

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

_pure_
static inline size_t buffer_size (buffer_t *buffer)
{
    return buffer->end-buffer->data;
}

_pure_
static inline size_t buffer_write_size (buffer_t *buffer)
{
    return buffer->end-buffer->write;
}

_pure_
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
            memcpy(buffer->data, src, size);
            buffer->read  -= src-buffer->data;
            buffer->write -= src-buffer->data;
        }
    }
}
