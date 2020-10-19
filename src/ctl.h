#pragma once

#include "../mud/mud.h"

#include <sys/socket.h>
#include <sys/un.h>

#define CTL_ERROR_NONE (-2)
#define CTL_ERROR_MANY (-3)

enum ctl_type {
    CTL_NONE = 0,
    CTL_STATUS,
    CTL_CONF,
    CTL_PATH_STATUS,
    CTL_PATH_CONF,
    CTL_ERRORS,
};

struct ctl_msg {
    enum ctl_type type;
    int reply, ret;
    char tun_name[64];
    union {
        struct {
            long pid;
            size_t mtu;
            int cipher;
            union mud_sockaddr local;
            union mud_sockaddr remote;
        } status;
        struct mud_conf conf;
        struct mud_path path;
        struct mud_errors errors;
    };
};

union ctl_sun {
    struct sockaddr sa;
    struct sockaddr_un sun;
};

char *ctl_rundir  (char *, size_t);
int   ctl_create  (const char *);
int   ctl_connect (const char *);
int   ctl_reply   (int, struct ctl_msg *, struct ctl_msg *);
void  ctl_delete  (int);
void  ctl_foreach (void (*cb) (const char *));

void ctl_explain_connect (int);
