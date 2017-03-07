#include "common.h"

#include "str.h"

#include <sys/ioctl.h>
#include <net/if.h>

int
iface_set_mtu(char *dev_name, int mtu)
{
    struct ifreq ifr = {
        .ifr_mtu = mtu,
    };

    str_cpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1)
        return -1;

    int ret = ioctl(fd, SIOCSIFMTU, &ifr);

    int err = errno;
    close(fd);
    errno = err;

    return ret;
}
