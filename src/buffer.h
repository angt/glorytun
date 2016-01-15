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
    if (buffer->read==buffer->data)
        return;

    if (buffer->read==buffer->write) {
        buffer_format(buffer);
        return;
    }

    const size_t size = buffer_read_size(buffer);

    memmove(buffer->data, buffer->read, size);

    buffer->read  = buffer->data;
    buffer->write = buffer->data+size;
}
