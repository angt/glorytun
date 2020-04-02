#include "common.h"

#include <sodium.h>

#include "../argz/argz.h"

int
gt_version(int argc, char **argv)
{
    struct argz version_argz[] = {
        {"libsodium", NULL, NULL, argz_option},
        {NULL}};

    if (argz(version_argz, argc, argv))
        return 1;

    if (argz_is_set(version_argz, "libsodium")) {
        printf("%i.%i (%s)\n",
               sodium_library_version_major(),
               sodium_library_version_minor(),
               sodium_version_string());
    } else {
        printf("%s\n", PACKAGE_VERSION);
    }

    return 0;
}
