#include "common.h"
#include "argz.h"

#include <inttypes.h>
#include <sodium.h>
#include <time.h>

#include "../mud/aegis256/aegis256.h"

#define NPUBBYTES 32
#define KEYBYTES  32
#define ABYTES    16

int
gt_bench(int argc, char **argv, void *data)
{
    struct argz z[] = {
        {"fallback", "Bench fallback cipher"},
        {0}};

    int err = argz(argc, argv, z);

    if (err)
        return err;

    if (sodium_init() == -1) {
        gt_log("sodium init failed\n");
        return -1;
    }
    int term = isatty(1);
    int fallback = argz_is_set(z, "fallback");

    if (!fallback && !aegis256_is_available()) {
        gt_log("%s is not available on your platform\n", GT_CIPHER(0));
        return -1;
    }
    unsigned char buf[1450 + ABYTES];
    unsigned char npub[NPUBBYTES];
    unsigned char key[KEYBYTES];

    memset(buf, 0, sizeof(buf));
    randombytes_buf(npub, sizeof(npub));
    randombytes_buf(key, sizeof(key));

    if (term) {
        printf("bench %s\n", GT_CIPHER(fallback));
        printf("  size       min           mean            max      \n");
        printf("----------------------------------------------------\n");
    }
    int64_t size = 20;

    for (int i = 0; !gt_quit && size <= 1450; i++) {
        struct {
            int64_t min, mean, max, n;
        } mbps = {.n = 0};

        int64_t bytes_max = (int64_t)1 << 24;

        while (!gt_quit && mbps.n < 10) {
            int64_t bytes = 0;
            int64_t base = (int64_t)clock();

            while (!gt_quit && bytes <= bytes_max) {
                if (fallback) {
                    crypto_aead_chacha20poly1305_encrypt(
                        buf, NULL, buf, size, NULL, 0, NULL, npub, key);
                } else {
                    aegis256_encrypt(buf, NULL, buf, size, NULL, 0, npub, key);
                }
                bytes += size;
            }
            int64_t dt = (int64_t)clock() - base;
            bytes_max = (bytes * (CLOCKS_PER_SEC / 3)) / dt;
            int64_t _mbps = (8 * bytes * CLOCKS_PER_SEC) / (dt * 1000 * 1000);

            if (!mbps.n++) {
                mbps.min = _mbps;
                mbps.max = _mbps;
                mbps.mean = _mbps;
                continue;
            }
            if (mbps.min > _mbps)
                mbps.min = _mbps;

            if (mbps.max < _mbps)
                mbps.max = _mbps;

            mbps.mean += (_mbps - mbps.mean) / mbps.n;

            if (term) {
                printf("\r %5"PRIi64" %9"PRIi64" Mbps %9"PRIi64" Mbps %9"PRIi64" Mbps",
                        size, mbps.min, mbps.mean, mbps.max);
                fflush(stdout);
            }
        }
        if (term) {
            printf("\n");
        } else {
            printf("bench %s %"PRIi64" %"PRIi64" %"PRIi64" %"PRIi64"\n",
                    GT_CIPHER(fallback), size, mbps.min, mbps.mean, mbps.max);
        }
        size += 2 * 5 * 13;
    }
    return 0;
}
