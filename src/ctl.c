#include "common.h"
#include "ctl.h"
#include "str.h"

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

int
ctl_reply(int fd, struct ctl_msg *res, struct ctl_msg *req)
{
    if (fd == -1) {
        errno = EINVAL;
        return -1;
    }

    if ((send(fd, req, sizeof(struct ctl_msg), 0) == -1) ||
        (recv(fd, res, sizeof(struct ctl_msg), 0) == -1))
        return -1;

    if (res->type != req->type || !res->reply) {
        errno = EINTR;
        return -1;
    }

    if (res->ret) {
        errno = res->ret;
        return -1;
    }

    return 0;
}

static int
ctl_setsun(struct sockaddr_un *dst, const char *dir, const char *file)
{
    struct sockaddr_un sun = {
        .sun_family = AF_UNIX,
    };

    int ret = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/%s", dir, file);

    if (ret <= 0 || (size_t)ret >= sizeof(sun.sun_path)) {
        errno = EINVAL;
        return -1;
    }

    if (dst)
        *dst = sun;

    return 0;
}

static int
ctl_bind(int fd, const char *dir, const char *file)
{
    struct sockaddr_un sun;

    if (str_empty(file)) {
        char name[10] = { [0] = '.' };
        unsigned pid = (unsigned)getpid();

        for (size_t i = 1; i < sizeof(name) - 1; i++, pid >>= 4)
            name[i] = "uncopyrightables"[pid & 15];

        if (ctl_setsun(&sun, dir, name))
            return -1;

        if (!bind(fd, (struct sockaddr *)&sun, sizeof(sun)))
            return 0;
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

    struct sockaddr_storage ss = { 0 };
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
ctl_connect(const char *dir, const char *file)
{
    DIR *dp = NULL;

    if (str_empty(dir)) {
        errno = EINVAL;
        return -1;
    }

    if (!file) {
        dp = opendir(dir);

        if (!dp)
            return -1;

        struct dirent *d = NULL;

        while (d = readdir(dp), d) {
            if (d->d_name[0] == '.')
                continue;

            if (file) {
                closedir(dp);
                return -3;
            }

            file = &d->d_name[0];
        }

        if (!file) {
            closedir(dp);
            return -2;
        }
    }

    struct sockaddr_un sun;
    const int ret = ctl_setsun(&sun, dir, file);

    if (dp) {
        int err = errno;
        closedir(dp);
        errno = err;
    }

    if (ret)
        return -1;

    int fd = ctl_create(dir, NULL);

    if (fd == -1)
        return -1;

    if (connect(fd, (struct sockaddr *)&sun, sizeof(sun))) {
        int err = errno;
        ctl_delete(fd);
        errno = err;
        return -1;
    }

    return fd;
}
