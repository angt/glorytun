#include "common.h"
#include "iface.h"
#include "str.h"

#include <net/if.h>
#include <sys/ioctl.h>

int
iface_set_mtu(const char *dev_name, size_t mtu)
{
    if (mtu > (size_t)0xFFFF) {
        errno = EINVAL;
        return -1;
    }

    struct ifreq ifr = {
        .ifr_mtu = (int)mtu,
    };

    const size_t len = sizeof(ifr.ifr_name) - 1;

    if (str_cpy(ifr.ifr_name, len, dev_name) == len) {
        if (str_len(dev_name, len + 1) > len) {
            errno = EINTR;
            return -1;
        }
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1)
        return -1;

    int ret = ioctl(fd, SIOCSIFMTU, &ifr);

    int err = errno;
    close(fd);
    errno = err;

    return ret;
}
