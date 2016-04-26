#include "common.h"

#include "state.h"
#include "str.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

int state_create (const char *filename)
{
    if (str_empty(filename))
        return -1;

    int fd = open(filename, O_WRONLY);

    if (fd==-1) {
        if (errno!=EINTR)
            perror("open");
        return -1;
    }

    struct stat st = {0};

    if (fstat(fd, &st)==-1) {
        perror("fstat");
        close(fd);
        return -1;
    }

    if (!S_ISFIFO(st.st_mode)) {
        gt_log("`%s' is not a fifo\n", filename);
        close(fd);
        return -1;
    }

    return fd;
}

void state_send (int fd, const char *state, const char *info)
{
    if (str_empty(state))
        return;

    if (fd==-1) {
        gt_print("%s %s\n", state, info);
        return;
    }

    const char *strs[] = { state, " ", info, "\n" };
    char *str = str_cat(strs, COUNT(strs));

    if (!str) {
        perror("str_cat");
        return;
    }

    if (write(fd, str, str_len(str))==-1 && errno!=EINTR)
        perror("write");

    free(str);
}
