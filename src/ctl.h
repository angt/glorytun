#pragma once

#include <sys/socket.h>

enum ctl_type {
    CTL_UNKNOWN,
    CTL_PATH_ADD,
    CTL_PATH_DEL,
    CTL_STATUS,
    CTL_STATUS_REPLY,
    CTL_REPLY,
};

struct ctl_msg {
    enum ctl_type type;
    union {
        struct {
            enum ctl_type type;
        } unknown;
        struct sockaddr_storage path_addr;
        struct {
            size_t mtu;
            int mtu_auto;
            int chacha;
            struct sockaddr_storage bind;
            struct sockaddr_storage peer;
        } status;
        int reply;
    };
};

int  ctl_create  (const char *, const char *);
int  ctl_connect (int, const char *, const char *);
void ctl_delete  (int);
