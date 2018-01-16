#pragma once

enum ctl_type {
    CTL_UNKNOWN,
    CTL_PING,
    CTL_PONG,
};

struct ctl_msg {
    enum ctl_type type;
    union {
        struct {
            enum ctl_type type;
        } unknown;
    };
};

int ctl_init    (const char *, const char *);
int ctl_connect (int, const char *, const char *);
