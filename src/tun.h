#pragma once

#include <stddef.h>

int tun_create      (char *, size_t, const char *);
int tun_read        (int, void *, size_t);
int tun_write       (int, const void *, size_t);
int tun_set_persist (int, int);
