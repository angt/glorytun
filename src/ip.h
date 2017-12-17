#pragma once

#include <stdint.h>

struct ip_common {
    uint8_t version;
    uint8_t tc;
    uint8_t proto;
    uint8_t hdr_size;
    uint16_t size;
};

_pure_ static inline uint8_t
ip_get_version(const uint8_t *data, size_t size)
{
    if (size < 20)
        return 0;

    return data[0] >> 4;
}

static inline uint32_t
ip_read32(const uint8_t *src)
{
    uint32_t ret = src[3];
    ret |= ((uint32_t)src[2]) << 8;
    ret |= ((uint32_t)src[1]) << 16;
    ret |= ((uint32_t)src[0]) << 24;
    return ret;
}

static inline uint16_t
ip_read16(const uint8_t *src)
{
    uint16_t ret = src[1];
    ret |= ((uint16_t)src[0]) << 8;
    return ret;
}

static inline int
ip_get_mtu(struct ip_common *ic, const uint8_t *data, size_t size)
{
    if (ic->hdr_size <= 0 || ic->hdr_size + 8 > size)
        return -1;

    const uint8_t *p = &data[ic->hdr_size];

    if (ic->version == 4 && ic->proto == 1 && p[0] == 3)
        return ip_read16(&p[6]);

    // not tested..
    // if (ic->version == 6 && ic->proto == 58 && p[0] == 2)
    //    return ip_read32(&p[4]);

    return -1;
}

static inline int
ip_get_common(struct ip_common *ic, const uint8_t *data, size_t size)
{
    ic->version = ip_get_version(data, size);

    switch (ic->version) {
    case 4:
        ic->tc = data[1];
        ic->proto = data[9];
        ic->hdr_size = (data[0] & 0xF) << 2;
        ic->size = ip_read16(&data[2]);
        if (ic->size >= 20)
            return 0;
        break;
    case 6:
        ic->tc = ((data[0] & 0xF) << 4) | (data[1] >> 4);
        ic->proto = data[6];
        ic->hdr_size = 40;
        ic->size = ip_read16(&data[4]) + 40;
        return 0;
    }

    return -1;
}
