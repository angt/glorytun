#pragma once

#include <stdint.h>

static inline int ip_get_version (const uint8_t *data, size_t size)
{
    if (size<20)   // XXX
        return -1; // XXX

    return data[0]>>4;
}

static inline ssize_t ip_get_size (const uint8_t *data, size_t size)
{
    switch (ip_get_version(data, size)) {
    case 4:
        return ((data[2]<<8)|data[3]);
    case 6:
        return ((data[4]<<8)|data[5])+40;
    case -1:
        return -1;
    }

    return 0;
}
