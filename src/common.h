#pragma once

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
#define GT_CIPHER(x) ((x) ? "chacha20poly1305" : "aegis256")

#define COUNT(x) (sizeof(x) / sizeof(x[0]))
#define EMPTY(x) ({ __typeof__(x) X=(x); !X || !X[0]; })

#define _printf_(A, B) __attribute__((format(printf, A, B)))

#undef MAX
#define MAX(x, y) ({ __typeof__(x) X=(x); __typeof__(y) Y=(y); X > Y ? X : Y; })

#undef MIN
#define MIN(x, y) ({ __typeof__(x) X=(x); __typeof__(y) Y=(y); X < Y ? X : Y; })

extern volatile sig_atomic_t gt_alarm;
extern volatile sig_atomic_t gt_reload;
extern volatile sig_atomic_t gt_quit;

void gt_log (const char *, ...) _printf_(1, 2);

int gt_tohex   (char *, size_t, const uint8_t *, size_t);
int gt_fromhex (uint8_t *, size_t, const char *, size_t);
