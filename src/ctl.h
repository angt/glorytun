#pragma once

enum ctl_type {
    CTL_UNKNOWN,
    CTL_PATH_ADD,
    CTL_PATH_DEL,
    CTL_PING,
    CTL_REPLY,
};

struct ctl_msg {
    enum ctl_type type;
    union {
        struct {
            enum ctl_type type;
        } unknown;
        struct {
            struct {
                char addr[256];
            } add, del;
        } path;
        int reply;
    };
};

int ctl_init    (const char *, const char *);
int ctl_connect (int, const char *, const char *);
