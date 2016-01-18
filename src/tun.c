#include "common.h"

#include "tun.h"
#include "str.h"
#include "ip.h"

#include <stdio.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#ifdef __APPLE__
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#endif

#if defined(__APPLE__) || defined(__OpenBSD__)
#define GT_BSD_TUN
#endif

#ifdef __APPLE__

static int tun_create_by_id (char *name, size_t size, unsigned id, _unused_ int mq)
{
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd==-1)
        return -1;

    struct ctl_info ci;

    memset(&ci, 0, sizeof(ci));
    str_cpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name)-1);

    if (ioctl(fd, CTLIOCGINFO, &ci)) {
        close(fd);
        return -1;
    }

    struct sockaddr_ctl sc = {
        .sc_id = ci.ctl_id,
        .sc_len = sizeof(sc),
        .sc_family = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_unit = id+1,
    };

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc))) {
        close(fd);
        return -1;
    }

    snprintf(name, size, "utun%u", id);

    return fd;
}

static int tun_create_by_name (char *name, size_t size, char *dev_name, int mq)
{
    unsigned id = 0;

    if (sscanf(dev_name, "utun%u", &id)!=1)
        return -1;

    return tun_create_by_id(name, size, id, mq);
}

#else /* not __APPLE__ */

#ifdef __linux__

static int tun_create_by_name (char *name, size_t size, char *dev_name, int mq)
{
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd==-1)
        return -1;

    struct ifreq ifr = {
        .ifr_flags = IFF_TUN|IFF_NO_PI,
    };

    if (mq) {
#ifdef IFF_MULTI_QUEUE
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
#endif
    }

    str_cpy(ifr.ifr_name, dev_name, IFNAMSIZ-1);

    if (ioctl(fd, TUNSETIFF, &ifr)) {
        close(fd);
        return -1;
    }

    str_cpy(name, ifr.ifr_name, size-1);

    return fd;
}

#else /* not __linux__ not __APPLE__ */

static int tun_create_by_name (char *name, size_t size, char *dev_name, _unused_ int mq)
{
    char path[64];

    snprintf(path, sizeof(path), "/dev/%s", dev_name);
    str_cpy(name, dev_name, size-1);

    return open(path, O_RDWR);
}

#endif /* not __APPLE__ */

static int tun_create_by_id (char *name, size_t size, unsigned id, int mq)
{
    char dev_name[64];

    snprintf(dev_name, sizeof(dev_name), "tun%u", id);

    return tun_create_by_name(name, size, dev_name, mq);
}

#endif

int tun_create (char *dev_name, char **ret_name, int mq)
{
    char name[64] = {0};
    int fd = -1;

#ifndef IFF_MULTI_QUEUE
    if (mq)
        gt_na("IFF_MULTI_QUEUE");
#endif

    if (str_empty(dev_name)) {
        for (unsigned id=0; id<32 && fd==-1; id++)
            fd = tun_create_by_id(name, sizeof(name), id, mq);
    } else {
        fd = tun_create_by_name(name, sizeof(name), dev_name, mq);
    }

    if (fd!=-1 && ret_name)
        *ret_name = strdup(name);

    return fd;
}

ssize_t tun_read (int fd, void *data, size_t size)
{
    if (!size)
        return -1;

#ifdef GT_BSD_TUN
    uint32_t family;

    struct iovec iov[2] = {
        { .iov_base = &family, .iov_len = sizeof(family) },
        { .iov_base = data, .iov_len = size }
    };

    ssize_t ret = readv(fd, iov, 2);
#else
    ssize_t ret = read(fd, data, size);
#endif

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;

        if (errno)
            perror("tun read");

        return 0;
    }

#ifdef GT_BSD_TUN
    if (ret<(ssize_t) sizeof(family))
        return 0;

    return ret-sizeof(family);
#else
    return ret;
#endif
}

ssize_t tun_write (int fd, const void *data, size_t size)
{
    if (!size)
        return -1;

#ifdef GT_BSD_TUN
    uint32_t family;

    switch (ip_get_version(data, size)) {
    case 4:
        family = htonl(AF_INET);
        break;
    case 6:
        family = htonl(AF_INET6);
        break;
    default:
        return -1;
    }

    struct iovec iov[2] = {
        { .iov_base = &family, .iov_len = sizeof(family) },
        { .iov_base = (void *) data, .iov_len = size },
    };

    ssize_t ret = writev(fd, iov, 2);
#else
    ssize_t ret = write(fd, data, size);
#endif

    if (ret==-1) {
        if (errno==EAGAIN || errno==EINTR)
            return -1;

        if (errno)
            perror("tun write");

        return 0;
    }

#ifdef GT_BSD_TUN
    if (ret<(ssize_t) sizeof(family))
        return 0;

    return ret-sizeof(family);
#else
    return ret;
#endif
}
