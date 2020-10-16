#include "common.h"
#include "ctl.h"
#include "argz.h"

int
gt_list(int argc, char **argv, void *data)
{
    int err = argz(argc, argv, NULL);

    if (err)
        return err;

    ctl_foreach(gt_argz_print);

    return 0;
}
