#pragma once

#include <stdint.h>

struct ip_common {
    uint8_t version;
    uint8_t proto;
    uint8_t hdr_size;
    uint16_t size;
};

_pure_
static inline uint8_t ip_get_version (const uint8_t *data, size_t size)
{
    if (size<20)
        return 0;

    return data[0]>>4;
}

static inline int ip_get_common (struct ip_common *ic, const uint8_t *data, size_t size)
{
    ic->version = ip_get_version(data, size);

    switch (ic->version) {
    case 4:
        ic->proto = data[9];
        ic->hdr_size = (data[0]&0xF)<<2;
        ic->size = ((data[2]<<8)|data[3]);
        return 0;
    case 6:
        ic->proto = data[6];
        ic->hdr_size = 40;
        ic->size = ((data[4]<<8)|data[5])+40;
        return 0;
    }

    return -1;
}
