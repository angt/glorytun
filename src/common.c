#include "common.h"

#include <stdio.h>
#include <stdarg.h>

int gt_print (const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = vfprintf(stdout, fmt, ap);
    va_end(ap);

    if (ret<0)
        return 0;

    return ret;
}

void gt_log (const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void gt_fatal (const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    exit(EXIT_FAILURE);
}

void gt_na (const char *name)
{
    gt_log("%s is not available on your platform\n", name);
}

int gt_tohex (char *dst, size_t dst_size, const uint8_t *src, size_t src_size)
{
    if _0_(!dst_size)
        return -1;

    if _0_(((dst_size-1)/2)<src_size)
        return -1;

    static const char tbl[] = "0123456789ABCDEF";

    for (size_t i=0; i<src_size; i++) {
        *dst++ = tbl[0xF&(src[i]>>4)];
        *dst++ = tbl[0xF&(src[i])];
    }

    *dst = 0;

    return 0;
}

_const_
static inline int fromhex (const char c)
{
    if (c>='0' && c<='9')
        return c-'0';

    if (c>='A' && c<='F')
        return c-'A'+10;

    if (c>='a' && c<='f')
        return c-'a'+10;

    return -1;
}

int gt_fromhex (uint8_t *dst, size_t dst_size, const char *src, size_t src_size)
{
    if _0_(src_size&1)
        return -1;

    if _0_(dst_size<(src_size/2))
        return -1;

    for (size_t i=0; i<src_size; i+=2) {
        const int a = fromhex(src[i]);
        const int b = fromhex(src[i+1]);

        if _0_(a==-1 || b==-1)
            return -1;

        *dst++ = (a<<4)|b;
    }

    return 0;
}
