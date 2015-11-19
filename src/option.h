#pragma once

struct option {
    char *name;
    void *data;
    int (*call) (void *, int, char **);
    int set;
};

int option_option (void *, int, char **);
int option_str    (void *, int, char **);
int option_long   (void *, int, char **);

int option_is_set (struct option *, const char *);
int option        (struct option *, int, char **);
