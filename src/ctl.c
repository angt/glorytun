#include "common.h"

#include "ctl.h"
#include "str.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

int
ctl_init(const char *dir, const char *file)
{
    if (str_empty(dir) || str_empty(file)) {
        errno = EINVAL;
        return -1;
    }

    if (mkdir(dir, 0700) == -1 && errno != EEXIST)
        return -1;

    const char *strs[] = {dir, "/", file};
    char *path = str_cat(strs, 3);

    if (!path)
        return -1;

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (fd == -1) {
        int err = errno;
        free(path);
        errno = err;
        return -1;
    }

    struct sockaddr_un sun = {
        .sun_family = AF_UNIX,
    };

    str_cpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);
    free(path);
    unlink(sun.sun_path);

    if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
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

    const char *strs[] = {dir, "/", file};
    char *path = str_cat(strs, 3);

    if (!path)
        return -1;

    struct sockaddr_un sun = {
        .sun_family = AF_UNIX,
    };

    str_cpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);
    free(path);

    return connect(fd, (struct sockaddr *)&sun, sizeof(sun));
}
