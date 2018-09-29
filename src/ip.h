#pragma once

#include <stdint.h>

struct ip_common {
    uint8_t tc;
    uint8_t proto;
    struct { // data are not reordered
        union {
            unsigned char v6[16];
            struct {
                unsigned char zero[10];
                unsigned char ff[2];
                unsigned char v4[4];
            };
        };
        unsigned char port[2];
    } src, dst;
};

static inline int
ip_read16(const uint8_t *src)
{
    uint16_t ret = src[1];
    ret |= ((uint16_t)src[0]) << 8;
    return (int)ret;
}

static inline uint8_t
ip_get_version(const uint8_t *data)
{
    return data[0] >> 4;
}

static inline int
ip_is_valid(const uint8_t *data, int size)
{
    if (size < 20)
        return 0;

    switch (ip_get_version(data)) {
        case 4: return size == ip_read16(&data[2]);
        case 6: return size == ip_read16(&data[4]) + 40;
    }

    return 0;
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
        if (size == ip_read16(&data[2])) {
            const int hdrsize = (data[0] & 0xF) << 2;
            memset(ic->src.zero, 0, sizeof(ic->src.zero));
            memset(ic->src.ff, 0xff, sizeof(ic->src.ff));
            memcpy(ic->src.v4, &data[12], sizeof(ic->src.v4));
            memset(ic->dst.zero, 0, sizeof(ic->dst.zero));
            memset(ic->dst.ff, 0xff, sizeof(ic->dst.ff));
            memcpy(ic->dst.v4, &data[16], sizeof(ic->dst.v4));
            switch (ic->proto) {
            case 6:  // tcp
            case 17: // udp
                memcpy(ic->src.port, &data[hdrsize], sizeof(ic->src.port));
                memcpy(ic->dst.port, &data[hdrsize + 2], sizeof(ic->dst.port));
                break;
            default:
                memset(ic->src.port, 0, sizeof(ic->src.port));
                memset(ic->dst.port, 0, sizeof(ic->dst.port));
            }
            return 0;
        }
        break;
    case 6:
        ic->tc = ((data[0] & 0xF) << 4) | (data[1] >> 4);
        ic->proto = data[6];
        if (size == ip_read16(&data[4]) + 40) {
            memcpy(ic->src.v6, &data[8], sizeof(ic->src.v6));
            memcpy(ic->dst.v6, &data[24], sizeof(ic->dst.v6));
            switch (ic->proto) {
            case 6:  // tcp
            case 17: // udp
                memcpy(ic->src.port, &data[40], sizeof(ic->src.port));
                memcpy(ic->dst.port, &data[42], sizeof(ic->dst.port));
                break;
            default:
                memset(ic->src.port, 0, sizeof(ic->src.port));
                memset(ic->dst.port, 0, sizeof(ic->dst.port));
            }
            return 0;
        }
        break;
    }

    return 1;
}
