#pragma once

#include <sys/socket.h>

enum ctl_type {
    CTL_NONE = 0,
    CTL_PATH_ADD,
    CTL_PATH_DEL,
    CTL_STATUS,
    CTL_MTU,
    CTL_TIMEOUT,
    CTL_TIMETOLERANCE,
};

struct ctl_msg {
    enum ctl_type type;
    int reply, ret;
    union {
        struct sockaddr_storage path_addr;
        struct {
            size_t mtu;
            int mtu_auto;
            int chacha;
            struct sockaddr_storage bind;
            struct sockaddr_storage peer;
        } status;
        int mtu;
        unsigned long timeout;
        unsigned long timetolerance;
    };
};

int  ctl_create  (const char *, const char *);
int  ctl_connect (int, const char *, const char *);
int  ctl_reply   (int, struct ctl_msg *, struct ctl_msg *);
void ctl_delete  (int);
