#include "common.h"

#include <stdio.h>

void gt_not_available (const char *name)
{
    fprintf(stderr, "%s is not available on your platform!\n", name);
}
