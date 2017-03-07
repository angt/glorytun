#pragma once

int tun_create      (char *, char **);
int tun_read        (int, void *, size_t);
int tun_write       (int, const void *, size_t);
int tun_set_persist (int, int);
