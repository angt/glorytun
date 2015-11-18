#include "common-static.h"
#include "ip-static.h"

#include "tun.h"

#include <stdio.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef __linux__
# include <linux/if.h>
# include <linux/if_tun.h>
#endif

#ifdef __APPLE__
# include <sys/sys_domain.h>
# include <sys/kern_control.h>
# include <net/if_utun.h>
#endif

#if defined(__APPLE__) || defined(__OpenBSD__)
# define GT_BSD_TUN 1
#endif

#ifdef __linux__
int tun_create (char *name, int multiqueue)
{
    int fd = open("/dev/net/tun", O_RDWR);

    if (fd<0) {
        perror("open /dev/net/tun");
        return -1;
    }

    struct ifreq ifr = {
        .ifr_flags = IFF_TUN|IFF_NO_PI,
    };

    if (multiqueue) {
#ifdef IFF_MULTI_QUEUE
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
#else
        gt_na("IFF_MULTI_QUEUE");
#endif
    }

    str_cpy(ifr.ifr_name, name, IFNAMSIZ-1);

    int ret = ioctl(fd, TUNSETIFF, &ifr);

    if (ret<0) {
        perror("ioctl TUNSETIFF");
        return -1;
    }

    gt_print("tun name: %s\n", ifr.ifr_name);

    return fd;
}
#elif defined(__APPLE__)
int tun_create (_unused_ char *name, _unused_ int mq)
{
    for (unsigned dev_id = 0U; dev_id<32U; dev_id++) {
        struct ctl_info ci;
        byte_set(&ci, 0, sizeof(ci));
        str_cpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name)-1);

        int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

        if (fd==-1)
            return -1;

        if (ioctl(fd, CTLIOCGINFO, &ci)==-1) {
            close(fd);
            continue;
        }

        struct sockaddr_ctl sc = {
            .sc_id = ci.ctl_id,
            .sc_len = sizeof(sc),
            .sc_family = AF_SYSTEM,
            .ss_sysaddr = AF_SYS_CONTROL,
            .sc_unit = dev_id+1,
        };

        if (connect(fd, (struct sockaddr *)&sc, sizeof(sc))==-1) {
            close(fd);
            continue;
        }

        gt_print("tun name: /dev/utun%u\n", dev_id);

        return fd;
    }

    return -1;
}
#else
int tun_create (_unused_ char *name, _unused_ int mq)
{
    for (unsigned dev_id = 0U; dev_id<32U; dev_id++) {
        char dev_path[11U];

        sngt_print(dev_path, sizeof(dev_path), "/dev/tun%u", dev_id);

        int fd = open(dev_path, O_RDWR);

        if (fd!=-1) {
            gt_print("tun name: /dev/tun%u\n", dev_id);
            return fd;
        }
    }

    return -1;
}
#endif

ssize_t tun_read (int fd, void *data, size_t size)
{
    if (!size)
        return -2;

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
            perror("readv");

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
        return -2;

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
            perror("write");

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
