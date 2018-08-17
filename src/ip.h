#pragma once

#include <stdint.h>

struct ip_common {
    uint8_t tc;
    uint8_t proto;
};

static inline uint8_t
ip_get_version(const uint8_t *data)
{
    return data[0] >> 4;
}

static inline int
ip_read16(const uint8_t *src)
{
    uint16_t ret = src[1];
    ret |= ((uint16_t)src[0]) << 8;
    return (int)ret;
}

static inline int
ip_get_common(struct ip_common *ic, const uint8_t *data, int size)
{
    if (size < 20)
        return 1;

    switch (ip_get_version(data)) {
    case 4:
        ic->tc = data[1];
        ic->proto = data[9];
        return size != ip_read16(&data[2]);
    case 6:
        ic->tc = ((data[0] & 0xF) << 4) | (data[1] >> 4);
        ic->proto = data[6];
        return size != ip_read16(&data[4]) + 40;
    }

    return 1;
}
