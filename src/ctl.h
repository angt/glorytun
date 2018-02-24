#pragma once

#include "../mud/mud.h"

#include <sys/socket.h>

enum ctl_type {
    CTL_NONE = 0,
    CTL_STATE,
    CTL_STATUS,
    CTL_MTU,
    CTL_TIMEOUT,
    CTL_TIMETOLERANCE,
};

struct ctl_msg {
    enum ctl_type type;
    int reply, ret;
    union {
        struct {
            struct sockaddr_storage addr;
            enum mud_state state;
        } path;
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
