#include "common.h"
#include "ip.h"
#include "str.h"
#include "tun.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>

#ifdef __linux__
#define IFF_TUN 0x0001
#define IFF_NO_PI 0x1000
#define TUNSETIFF _IOW('T', 202, int)
#define TUNSETPERSIST _IOW('T', 203, int)
#endif

#ifdef __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#if defined(__APPLE__) || defined(__OpenBSD__)
#define GT_BSD_TUN
#endif

#ifdef __APPLE__

static int
tun_create_by_id(char *name, size_t len, unsigned id)
{
    int ret = snprintf(name, len + 1, "utun%u", id);

    if (ret <= 0 || ret > len) {
        errno = EINVAL;
        return -1;
    }

    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd == -1)
        return -1;

    struct ctl_info ci = {0};
    str_cpy(ci.ctl_name, sizeof(ci.ctl_name) - 1, UTUN_CONTROL_NAME);

    if (ioctl(fd, CTLIOCGINFO, &ci)) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }

    struct sockaddr_ctl sc = {
        .sc_id = ci.ctl_id,
        .sc_len = sizeof(sc),
        .sc_family = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_unit = id + 1,
    };

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc))) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }

    return fd;
}

static int
tun_create_by_name(char *name, size_t len, const char *dev_name)
{
    unsigned id = 0;

    if (sscanf(dev_name, "utun%u", &id) != 1) {
        errno = EINVAL;
        return -1;
    }

    return tun_create_by_id(name, len, id);
}

#else /* not __APPLE__ */

#ifdef __linux__

static int
tun_create_by_name(char *name, size_t len, const char *dev_name)
{
    struct ifreq ifr = {
        .ifr_flags = IFF_TUN | IFF_NO_PI,
    };

    const size_t ifr_len = sizeof(ifr.ifr_name) - 1;

    if ((len < ifr_len) ||
        (str_len(dev_name, ifr_len + 1) > ifr_len)) {
        errno = EINVAL;
        return -1;
    }

    int fd = open("/dev/net/tun", O_RDWR);

    if (fd == -1)
        return -1;

    str_cpy(ifr.ifr_name, ifr_len, dev_name);

    if (ioctl(fd, TUNSETIFF, &ifr)) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }

    str_cpy(name, len, ifr.ifr_name);

    return fd;
}

#else /* not __linux__ not __APPLE__ */

static int
tun_create_by_name(char *name, size_t len, const char *dev_name)
{
    char tmp[128];
    int ret = snprintf(tmp, sizeof(tmp), "/dev/%s", dev_name);

    if (ret <= 0 || (size_t)ret >= sizeof(tmp)) {
        errno = EINVAL;
        return -1;
    }

    if (str_cpy(name, len, dev_name) == len) {
        if (str_len(dev_name, len + 1) > len) {
            errno = EINVAL;
            return -1;
        }
    }

    return open(tmp, O_RDWR);
}

#endif /* not __APPLE__ */

static int
tun_create_by_id(char *name, size_t len, unsigned id)
{
    char tmp[64];
    int ret = snprintf(tmp, sizeof(tmp), "tun%u", id);

    if (ret <= 0 || (size_t)ret >= sizeof(tmp)) {
        errno = EINVAL;
        return -1;
    }

    return tun_create_by_name(name, len, tmp);
}

#endif

int
tun_create(char *name, size_t len, const char *dev_name)
{
    int fd = -1;

    if (str_empty(dev_name)) {
        for (unsigned id = 0; id < 32 && fd == -1; id++)
            fd = tun_create_by_id(name, len, id);
    } else {
        fd = tun_create_by_name(name, len, dev_name);
    }

    return fd;
}

int
tun_read(int fd, void *data, size_t size)
{
    if (!size)
        return 0;

#ifdef GT_BSD_TUN
    uint32_t family;

    struct iovec iov[2] = {
        {
            .iov_base = &family,
            .iov_len = sizeof(family),
        },
        {
            .iov_base = data,
            .iov_len = size,
        },
    };

    int ret = (int)readv(fd, iov, 2);

    if (ret <= 0)
        return ret;

    if ((size_t)ret <= sizeof(family))
        return 0;

    return ret - (int)sizeof(family);
#else
    return (int)read(fd, data, size);
#endif
}

int
tun_write(int fd, const void *data, size_t size)
{
    if (!size)
        return 0;

#ifdef GT_BSD_TUN
    uint32_t family;

    switch (ip_get_version(data, (int)size)) {
    case 4:
        family = htonl(AF_INET);
        break;
    case 6:
        family = htonl(AF_INET6);
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    struct iovec iov[2] = {
        {
            .iov_base = &family,
            .iov_len = sizeof(family),
        },
        {
            .iov_base = (void *)data,
            .iov_len = size,
        },
    };

    int ret = (int)writev(fd, iov, 2);

    if (ret <= 0)
        return ret;

    if ((size_t)ret <= sizeof(family))
        return 0;

    return ret - (int)sizeof(family);
#else
    return (int)write(fd, data, size);
#endif
}

int
tun_set_persist(int fd, int on)
{
#ifdef TUNSETPERSIST
    return ioctl(fd, TUNSETPERSIST, on);
#else
    errno = ENOSYS;
    return -1;
#endif
}
