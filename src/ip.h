#pragma once

#include <stdint.h>

static inline int
ip_read16(const uint8_t *src)
{
    return ((int)src[1]) | (((int)src[0]) << 8);
}

static inline uint8_t
ip_get_version(const uint8_t *data, int size)
{
    if (size < 20)
        return 0;

    return data[0] >> 4;
}

static inline int
ip_is_valid(const uint8_t *data, int size)
{
    switch (ip_get_version(data, size)) {
        case 4: return size == ip_read16(&data[2]);
        case 6: return size == ip_read16(&data[4]) + 40;
    }
    return 0;
}
