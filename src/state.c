#include "common.h"

#include "state.h"
#include "str.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

static int state_fd = -1;

int state_init (const char *filename)
{
    if (str_empty(filename))
        return 0;

    state_fd = open(filename, O_WRONLY);

    if (state_fd==-1) {
        if (errno!=EINTR)
            perror("open");
        return -1;
    }

    struct stat st = {0};

    if (fstat(state_fd, &st)==-1) {
        perror("fstat");
        close(state_fd);
        state_fd = -1;
        return -1;
    }

    if (!S_ISFIFO(st.st_mode)) {
        gt_log("`%s' is not a fifo\n", filename);
        close(state_fd);
        state_fd = -1;
        return -1;
    }

    return 0;
}

void state (const char *state, const char *info)
{
    if (str_empty(state))
        return;

    const char *strs[] = { state, " ", info, "\n" };
    char *str = str_cat(strs, COUNT(strs));

    if (!str)
        return;

    if (state_fd==-1) {
        gt_print("%s", str);
    } else {
        if (write(state_fd, str, str_len(str))==-1 && errno!=EINTR)
            perror("write");
    }
}
