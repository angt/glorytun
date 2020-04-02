#pragma once

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifndef PACKAGE_NAME
#define PACKAGE_NAME "glorytun"
#endif

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "0.0.0"
#endif

#define COUNT(x) (sizeof(x) / sizeof(x[0]))

#define _1_(x) (__builtin_expect((x), 1))
#define _0_(x) (__builtin_expect((x), 0))
#define CLZ(x) (__builtin_clz(x))

#define _printf_(A, B) __attribute__((format(printf, A, B)))
#define _noreturn_     __attribute__((noreturn))
#define _unused_       __attribute__((unused))
#define _pure_         __attribute__((pure))
#define _const_        __attribute__((const))
#define _align_(...)   __attribute__((aligned(__VA_ARGS__)))

#undef MAX
#define MAX(x, y) ({ __typeof__(x) X=(x); __typeof__(y) Y=(y); X > Y ? X : Y; })

#undef MIN
#define MIN(x, y) ({ __typeof__(x) X=(x); __typeof__(y) Y=(y); X < Y ? X : Y; })

#define EMPTY(x) ({ __typeof__(x) X=(x); !X || !X[0]; })

#define GT_CIPHER(x) ((x) ? "chacha20poly1305" : "aegis256")

extern volatile sig_atomic_t gt_alarm;
extern volatile sig_atomic_t gt_reload;
extern volatile sig_atomic_t gt_quit;

int  gt_print (const char *, ...) _printf_(1, 2);
void gt_log   (const char *, ...) _printf_(1, 2);

int gt_tohex   (char *, size_t, const uint8_t *, size_t);
int gt_fromhex (uint8_t *, size_t, const char *, size_t);

void     gt_set_port (struct sockaddr *, uint16_t);
uint16_t gt_get_port (struct sockaddr *);

int gt_toaddr (char *, size_t, struct sockaddr *);

int gt_list    (int, char **);
int gt_show    (int, char **);
int gt_bind    (int, char **);
int gt_path    (int, char **);
int gt_keygen  (int, char **);
int gt_bench   (int, char **);
int gt_set     (int, char **);
int gt_version (int, char **);
