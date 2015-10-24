#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdint.h>

#define COUNT(x) (sizeof(x)/sizeof(x[0]))

#define ALIGN_SIZE     (1<<4)
#define ALIGN_MASK     (ALIGN_SIZE-1)

#define ALIGN(x)       (((x)+ALIGN_MASK)&~ALIGN_MASK)
#define ALIGN_DOWN(x)  ((x)&~ALIGN_MASK)

#define PALIGN(x)      ((void *)ALIGN((size_t)(x)))
#define PALIGN_DOWN(x) ((void *)ALIGN_DOWN((size_t)(x)))

typedef struct buffer buffer_t;

struct buffer {
    uint8_t *data;
    uint8_t *read;
    uint8_t *write;
    uint8_t *end;
};
