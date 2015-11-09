#pragma once

struct option {
    char *name;
    void *data;
    int (*call) (void *, int, char **);
};

int option_flag   (void *, int, char **);
int option_str    (void *, int, char **);
int option_long   (void *, int, char **);
int option_option (void *, int, char **);

int option (struct option *, int, char **);
