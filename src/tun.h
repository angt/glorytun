#pragma once

#include <unistd.h>

int     tun_create (char *, char **, int);
ssize_t tun_read   (int, void *, size_t);
ssize_t tun_write  (int, const void *, size_t);
