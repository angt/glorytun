#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define COUNT(x)       (sizeof(x)/sizeof(x[0]))

#define ALIGN_SIZE     (1<<4)
#define ALIGN_MASK     (ALIGN_SIZE-1)

#define ALIGN(x)       (((x)+ALIGN_MASK)&~ALIGN_MASK)
#define ALIGN_DOWN(x)  ((x)&~ALIGN_MASK)

#define PALIGN(x)      ((void *)ALIGN((size_t)(x)))
#define PALIGN_DOWN(x) ((void *)ALIGN_DOWN((size_t)(x)))

#define _1_(x)         (__builtin_expect((x), 1))
#define _0_(x)         (__builtin_expect((x), 0))

#define CLZ(x)         (__builtin_clz(x))

#define _printf_(A,B)  __attribute__ ((format(printf,A,B)))
#define _noreturn_     __attribute__ ((noreturn))
#define _unused_       __attribute__ ((unused))
#define _pure_         __attribute__ ((pure))
#define _const_        __attribute__ ((const))
#define _align_(...)   __attribute__ ((aligned(__VA_ARGS__)))

int  gt_print (const char *, ...) _printf_(1,2);
void gt_log   (const char *, ...) _printf_(1,2);
void gt_fatal (const char *, ...) _printf_(1,2) _noreturn_;
void gt_na    (const char *);

int gt_tohex   (char *, size_t, const uint8_t *, size_t);
int gt_fromhex (uint8_t *, size_t, const char *, size_t);
