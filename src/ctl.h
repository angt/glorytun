#pragma once

#include "../mud/mud.h"

#include <sys/socket.h>

enum ctl_type {
    CTL_NONE = 0,
    CTL_STATE,
    CTL_STATUS,
    CTL_MTU,
    CTL_TC,
    CTL_KXTIMEOUT,
    CTL_TIMETOLERANCE,
    CTL_PATH_STATUS,
    CTL_SYNC,
};

struct ctl_msg {
    enum ctl_type type;
    int reply, ret;
    union {
        struct {
            struct sockaddr_storage addr;
            enum mud_state state;
        } path;
        struct mud_path path_status;
        struct {
            long pid;
            size_t mtu;
            int chacha;
            struct sockaddr_storage bind;
            struct sockaddr_storage peer;
        } status;
        size_t mtu;
        int tc;
        unsigned long ms;
    };
};

int  ctl_create  (const char *, const char *);
int  ctl_connect (const char *, const char *);
int  ctl_reply   (int, struct ctl_msg *, struct ctl_msg *);
void ctl_delete  (int);
