#include "common.h"
#include "argz.h"

#include <sodium.h>

int
gt_version(int argc, char **argv, void *data)
{
    int err = argz(argc, argv, NULL);

    if (err)
        return err;

    printf("%s libsodium %i.%i\n",
           PACKAGE_VERSION,
           sodium_library_version_major(),
           sodium_library_version_minor());

    return 0;
}
