#include "common.h"
#include "ctl.h"

#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>

char *
ctl_rundir(char *dst, size_t size)
{
    if (dst && size)
        dst[0] = 0;

    const char *fmt[] = {
        "/run/user/%u/" PACKAGE_NAME,
        "/run/"         PACKAGE_NAME ".%u",
        "/var/run/"     PACKAGE_NAME ".%u",
        "/tmp/"         PACKAGE_NAME ".%u",
    };
    for (unsigned i = 0; i < COUNT(fmt); i++) {
        char path[128];
        int ret = snprintf(dst, size, fmt[i], geteuid());

        if ((ret <= 0) ||
            ((size_t)ret >= size) ||
            ((size_t)ret >= sizeof(path)))
            continue;

        memcpy(path, dst, (size_t)ret + 1);
        char *p = dirname(path);

        if (p && !access(p, W_OK))
            return dst;
    }
    errno = EPERM;
    return NULL;
}

int
ctl_reply(int fd, struct ctl_msg *res, struct ctl_msg *req)
{
    if ((send(fd, req, sizeof(struct ctl_msg), 0) == -1) ||
        (recv(fd, res, sizeof(struct ctl_msg), 0) == -1))
        return -1;

    if (res->type != req->type || !res->reply) {
        errno = EBADMSG;
        return -1;
    }
    if (res->ret) {
        errno = res->ret;
        return -1;
    }
    return 0;
}

static int
ctl_setsun(union ctl_sun *dst, const char *dir, const char *file)
{
    struct sockaddr_un sun = {
        .sun_family = AF_UNIX,
    };
    int ret = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/%s", dir, file);

    if (ret <= 0 || (size_t)ret >= sizeof(sun.sun_path)) {
        errno = EINVAL;
        return -1;
    }
    dst->sun = sun;
    return 0;
}

static int
ctl_bind(int fd, const char *dir, const char *file)
{
    char name[10] = {[0] = '.'};
    union ctl_sun sock;

    if (EMPTY(file)) {
        unsigned long pid = (unsigned long)getpid();

        for (size_t i = 1; i < sizeof(name) - 1; i++, pid >>= 4)
            name[i] = "uncopyrightables"[pid & 15];

        file = name;
    }
    if (ctl_setsun(&sock, dir, file))
        return -1;

    if (unlink(sock.sun.sun_path) && errno != ENOENT)
        return -1;

    return bind(fd, &sock.sa, sizeof(sock));
}

void
ctl_delete(int fd)
{
    union ctl_sun sock;
    socklen_t slen = sizeof(sock);

    if (!getsockname(fd, &sock.sa, &slen) && sock.sa.sa_family == AF_UNIX)
        unlink(sock.sun.sun_path);

    close(fd);
}

int
ctl_create(const char *file)
{
    char dir[64];

    if (!ctl_rundir(dir, sizeof(dir)))
        return -1;

    if (mkdir(dir, 0700) == -1 && errno != EEXIST)
        return -1;

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (ctl_bind(fd, dir, file)) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    return fd;
}

int
ctl_connect(const char *file)
{
    char dir[64];
    DIR *dp = NULL;

    if (!ctl_rundir(dir, sizeof(dir)))
        return -1;

    if (!file) {
        if (dp = opendir(dir), !dp)
            return CTL_ERROR_NONE;

        struct dirent *d = NULL;

        while (d = readdir(dp), d) {
            if (d->d_name[0] == '.')
                continue;

            if (file) {
                closedir(dp);
                return CTL_ERROR_MANY;
            }
            file = &d->d_name[0];
        }
        if (!file) {
            closedir(dp);
            return CTL_ERROR_NONE;
        }
    }
    union ctl_sun sock;
    const int ret = ctl_setsun(&sock, dir, file);

    if (dp) {
        int err = errno;
        closedir(dp);
        errno = err;
    }
    if (ret)
        return -1;

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

    if (ctl_bind(fd, dir, NULL) ||
        connect(fd, &sock.sa, sizeof(sock))) {
        int err = errno;
        ctl_delete(fd);
        errno = err;
        return -1;
    }
    return fd;
}

void
ctl_foreach(void (*cb)(const char *))
{
    char dir[64];

    if (!ctl_rundir(dir, sizeof(dir)))
        return;

    DIR *dp = opendir(dir);

    if (!dp)
        return;

    struct dirent *d = NULL;

    while (d = readdir(dp), d) {
        if (d->d_name[0] == '.')
            continue;

        int fd = ctl_connect(d->d_name);

        if (fd < 0)
            continue;

        cb(d->d_name);
        close(fd);
    }
    closedir(dp);
}

void
ctl_explain_connect(int ret)
{
    switch (ret) {
        case 0: break;
        case CTL_ERROR_MANY: gt_log("please select a tunnel\n"); break;
        case CTL_ERROR_NONE: gt_log("no active tunnel\n");       break;
        default:             gt_log("unknown error\n");          break;
        case -1: switch (errno) {
            case 0: break;
            case ENOENT:     gt_log("tunnel not found\n");       break;
            default:         perror("connect");                  break;
        }
    }
}
