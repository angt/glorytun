#include "common.h"

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

#include "../argz/argz.h"
#include "../mud/aegis256/aegis256.h"

#define NPUBBYTES 32
#define KEYBYTES  32
#define ABYTES    16

int
gt_bench(int argc, char **argv)
{
    struct argz bench_argz[] = {
        {"aes|chacha", NULL, NULL, argz_option},
        {NULL}};

    if (argz(bench_argz, argc, argv))
        return 1;

    if (sodium_init() == -1) {
        gt_log("sodium init failed\n");
        return 1;
    }

    int term = isatty(1);
    int aes = argz_is_set(bench_argz, "aes");
    int chacha = argz_is_set(bench_argz, "chacha");

    if (!aegis256_is_available()) {
        if (aes) {
            gt_log("aes is not available on your platform\n");
            return 1;
        }
        chacha = 1;
    }

    unsigned char buf[1450 + ABYTES];
    unsigned char npub[NPUBBYTES];
    unsigned char key[KEYBYTES];

    memset(buf, 0, sizeof(buf));
    randombytes_buf(npub, sizeof(npub));
    randombytes_buf(key, sizeof(key));

    if (term) {
        printf("cipher: %s\n\n", chacha ? "chacha20poly1305" : "aegis256");
        printf(" %5s %9s      %9s\n", "size", "mean", "sigma");
        printf("---------------------------------\n");
    }

    int64_t size = 20;

    for (int i = 0; !gt_quit && size <= 1450; i++) {
        struct {
            int64_t d, n, m, v, s;
        } s = { .n = 0 };

        while (!gt_quit && s.n < 5) {
            alarm(1);
            gt_alarm = 0;

            int64_t bytes = 0;
            clock_t base = clock();

            while (!gt_alarm && !(bytes >> 32)) {
                if (chacha) {
                    crypto_aead_chacha20poly1305_encrypt(
                            buf, NULL, buf, size, NULL, 0, NULL, npub, key);
                } else {
                    aegis256_encrypt(buf, NULL, buf, size, NULL, 0, npub, key);
                }
                bytes += size;
            }

            int64_t mbps = (8 * bytes * CLOCKS_PER_SEC)
                         / ((clock() - base) * 1000 * 1000);

            alarm(0);

            if (mbps <= 0)
                continue;

            if (!s.n++) {
                s.m = mbps;
                s.d = 0;
                continue;
            }

            int64_t d1 = mbps - s.m; s.m += d1 / s.n;
            int64_t d2 = mbps - s.m; s.d += d1 * d2;

            s.v = s.d / (s.n - 1);
            s.s = 1 + (s.v - 1) / 2;

            while (s.s && s.s * s.s > s.v)
                s.s = (s.s + s.v / s.s) / 2;

            if (term) {
                printf("\r %5"PRIi64" %9"PRIi64" Mbps %9"PRIi64, size, s.m, s.s);
                fflush(stdout);
            }
        }

        if (term) {
            printf("\n");
        } else {
            printf("bench %"PRIi64" %"PRIi64" %"PRIi64"\n", size, s.m, s.s);
        }

        size += 2 * 11 * 13;
    }

    return 0;
}
