#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

static int
ctl_setsun(struct sockaddr_un *dst, const char *dir, const char *file)
{
    struct sockaddr_un sun = {
        .sun_family = AF_UNIX,
    };

    const char *path[] = {dir, "/", file};
    const size_t len = sizeof(sun.sun_path) - 1;

    if (str_cat(sun.sun_path, len, path, COUNT(path)) == len) {
        if (str_cat(NULL, len + 1, path, COUNT(path)) > len) {
            errno = EINVAL;
            return -1;
        }
    }

    *dst = sun;

    return 0;
}

static int
ctl_bind(int fd, const char *dir, const char *file)
{
    char tmp[32];
    struct sockaddr_un sun;

    if (str_empty(file)) {
        for (int i = 0; i < 64; i++) {
            if (snprintf(tmp, sizeof(tmp), ".%i", i) >= sizeof(tmp))
                return -1;

            if (ctl_setsun(&sun, dir, tmp))
                return -1;

            if (!bind(fd, (struct sockaddr *)&sun, sizeof(sun)))
                return 0;
        }
    } else {
        if (ctl_setsun(&sun, dir, file))
            return -1;

        unlink(sun.sun_path);

        if (!bind(fd, (struct sockaddr *)&sun, sizeof(sun)))
            return 0;
    }

    return -1;
}

void
ctl_delete(int fd)
{
    if (fd == -1)
        return;

    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);

    if ((getsockname(fd, (struct sockaddr *)&ss, &sslen) == 0) &&
        (ss.ss_family == AF_UNIX))
        unlink(((struct sockaddr_un *)&ss)->sun_path);

    close(fd);
}

int
ctl_create(const char *dir, const char *file)
{
    if (str_empty(dir)) {
        errno = EINVAL;
        return -1;
    }

    if (mkdir(dir, 0700) == -1 && errno != EEXIST)
        return -1;

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (fd == -1)
        return -1;

    if (ctl_bind(fd, dir, file)) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }

    return fd;
}

int
ctl_connect(int fd, const char *dir, const char *file)
{
    if (fd < 0 || str_empty(dir) || str_empty(file)) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_un sun;

    if (ctl_setsun(&sun, dir, file))
        return -1;

    return connect(fd, (struct sockaddr *)&sun, sizeof(sun));
}
