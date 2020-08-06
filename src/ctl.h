#pragma once

#include "../mud/mud.h"

#include <sys/socket.h>

#define CTL_ERROR_NONE (-2)
#define CTL_ERROR_MANY (-3)

enum ctl_type {
    CTL_NONE = 0,
    CTL_STATE,
    CTL_CONF,
    CTL_STATUS,
    CTL_PATH_STATUS,
    CTL_BAD,
};

struct ctl_msg {
    enum ctl_type type;
    int reply, ret;
    union {
        struct {
            struct sockaddr_storage local_addr;
            struct sockaddr_storage addr;
            enum mud_state state;
            unsigned long rate_tx;
            unsigned long rate_rx;
            unsigned long beat;
            unsigned char fixed_rate;
            unsigned char loss_limit;
        } path;
        struct {
            char tun_name[64];
            long pid;
            size_t mtu;
            int chacha;
            struct sockaddr_storage bind;
            struct sockaddr_storage peer;
        } status;
        struct mud_conf conf;
        struct mud_path path_status;
        struct mud_bad bad;
    };
};

char *ctl_rundir  (char *, size_t);
int   ctl_create  (const char *);
int   ctl_connect (const char *);
int   ctl_reply   (int, struct ctl_msg *, struct ctl_msg *);
void  ctl_delete  (int);

void ctl_explain_connect (int);
