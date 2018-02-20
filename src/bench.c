#include "common.h"

#include <math.h>
#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined __APPLE__
#include <mach/mach_time.h>
#endif

#include "../argz/argz.h"

#define STR_S(X) (((X) > 1) ? "s" : "")

static unsigned long long
gt_now(void)
{
#if defined __APPLE__
    static mach_timebase_info_data_t mtid;
    if (!mtid.denom)
        mach_timebase_info(&mtid);
    return (mach_absolute_time() * mtid.numer / mtid.denom) / 1000ULL;
#elif defined CLOCK_MONOTONIC
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return tv.tv_sec * 1000000ULL + tv.tv_nsec / 1000ULL;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ULL + tv.tv_usec;
#endif
}

int
gt_bench(int argc, char **argv)
{
    unsigned long precision = 10;
    size_t bufsize = 64 * 1024;
    unsigned long duration = 1000;

    struct argz bench_argz[] = {
        {"aes|chacha", NULL, NULL, argz_option},
        {"precision", "EXPONENT", &precision, argz_ulong},
        {"bufsize", "BYTES", &bufsize, argz_bytes},
        {"duration", "SECONDS", &duration, argz_time},
        {NULL}};

    if (argz(bench_argz, argc, argv))
        return 1;

    if (duration == 0 || bufsize == 0)
        return 0;

    if (sodium_init() == -1) {
        gt_log("sodium init failed\n");
        return 1;
    }

    duration /= 1000;

    int term = isatty(1);
    int chacha = argz_is_set(bench_argz, "chacha");

    if (!chacha && !crypto_aead_aes256gcm_is_available()) {
        gt_log("aes is not available on your platform\n");
        return 1;
    }

    unsigned char *buf = calloc(1, bufsize + crypto_aead_aes256gcm_ABYTES);

    if (!buf) {
        perror("calloc");
        return 1;
    }

    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];

    randombytes_buf(npub, sizeof(npub));
    randombytes_buf(key, sizeof(key));

    if (term) {
        printf("\n");
        printf("  %-10s %s\n", "bench", chacha ? "chacha20poly1305" : "aes256gcm");
        printf("  %-10s %s\n", "libsodium", sodium_version_string());
        printf("\n");
        printf("  %-10s 2^(-%lu)\n", "precision", precision);
        printf("  %-10s %zu byte%s\n", "bufsize", bufsize, STR_S(bufsize));
        printf("  %-10s %lu second%s\n", "duration", duration, STR_S(duration));
        printf("\n");
        printf("------------------------------------------------------------\n");
        printf(" %3s %9s %14s %14s %14s\n", "2^n", "min", "avg", "max", "delta");
        printf("------------------------------------------------------------\n");
    }

    for (int i = 0; !gt_quit && bufsize >> i; i++) {
        unsigned long long total_dt = 0ULL;
        size_t total_bytes = 0;
        double mbps = 0.0;
        double mbps_min = INFINITY;
        double mbps_max = 0.0;
        double mbps_dlt = INFINITY;

        while (!gt_quit && mbps_dlt > ldexp(mbps, -precision)) {
            crypto_aead_aes256gcm_state ctx;

            if (!chacha)
                crypto_aead_aes256gcm_beforenm(&ctx, key);

            unsigned long long now = gt_now();
            double mbps_old = mbps;
            size_t bytes = 0;

            gt_alarm = 0;
            alarm(duration);

            while (!gt_quit && !gt_alarm) {
                if (chacha) {
                    crypto_aead_chacha20poly1305_encrypt(
                        buf, NULL, buf, 1ULL << i, NULL, 0, NULL, npub, key);
                } else {
                    crypto_aead_aes256gcm_encrypt_afternm(
                        buf, NULL, buf, 1ULL << i, NULL, 0, NULL, npub,
                        (const crypto_aead_aes256gcm_state *)&ctx);
                }
                bytes += 1ULL << i;
            }

            total_dt += gt_now() - now;
            total_bytes += bytes;

            mbps = (total_bytes * 8.0) / total_dt;
            mbps_min = fmin(mbps_min, mbps);
            mbps_max = fmax(mbps_max, mbps);
            mbps_dlt = fabs(mbps_old - mbps);

            if (term) {
                printf("\r %3i %9.2f Mbps %9.2f Mbps %9.2f Mbps %9.2e",
                       i, mbps_min, mbps, mbps_max, mbps_dlt);
                fflush(stdout);
            }
        }

        if (term) {
            printf("\n");
        } else {
            printf("%i %.2f %.2f %.2f\n", i, mbps_min, mbps, mbps_max);
        }
    }

    printf("\n");
    free(buf);

    return 0;
}
