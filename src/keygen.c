#include "common.h"
#include "argz.h"

#include <sodium.h>

int
gt_keygen(int argc, char **argv, void *data)
{
    int err = argz(argc, argv, NULL);

    if (err)
        return err;

    if (sodium_init() == -1) {
        gt_log("sodium init failed\n");
        return -1;
    }
    unsigned char key[32];
    randombytes_buf(key, sizeof(key));

    char buf[2 * sizeof(key) + 1];
    gt_tohex(buf, sizeof(buf), key, sizeof(key));
    printf("%s\n", buf);

    return 0;
}
