#pragma once

#include <stdint.h>

_pure_
static inline int ip_get_version (const uint8_t *data, size_t size)
{
    if (size<20)   // XXX
        return -1; // XXX

    return data[0]>>4;
}

_pure_
static inline ssize_t ip_get_size (const int ip_version, const uint8_t *data, size_t size)
{
    switch (ip_version) {
    case 4:
        return ((data[2]<<8)|data[3]);
    case 6:
        return ((data[4]<<8)|data[5])+40;
    case -1:
        return -1;
    }

    return 0;
}

_pure_
static inline ssize_t ip_get_proto (const int ip_version, const uint8_t *data, size_t size)
{
    switch (ip_version) {
    case 4:
        return data[9];
    case 6:
        return data[6];
    case -1:
        return -1;
    }

    return 0;
}

_pure_
static inline ssize_t ip_get_hdr_size (const int ip_version, const uint8_t *data, size_t size)
{
    switch (ip_version) {
    case 4:
        return (data[0]&0xF)<<2;
    case 6:
        return 40;
    case -1:
        return -1;
    }

    return 0;
}
