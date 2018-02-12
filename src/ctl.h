#pragma once

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
        struct {
            struct {
                char addr[256];
            } add, del;
        } path;
        struct {
            size_t mtu;
            int mtu_auto;
            int chacha;
            char addr[256];
            unsigned short port;
            unsigned short bind_port;
            int ipv4;
            int ipv6;
        } status;
        int reply;
    };
};

int  ctl_create  (const char *, const char *);
int  ctl_connect (int, const char *, const char *);
void ctl_delete  (int);
