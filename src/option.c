#include "common-static.h"

#include <stdio.h>
#include <stdlib.h>

#include "option.h"

int option_flag (void *data, _unused_ int argc, _unused_ char **argv)
{
    const int one = 1;
    byte_cpy(data, &one, sizeof(one));

    return 0;
}

int option_str (void *data, int argc, char **argv)
{
    if (argc<2 || !argv[1]) {
        gt_print("option `%s' need a string argument\n", argv[0]);
        return -1;
    }

    byte_cpy(data, &argv[1], sizeof(argv[1]));

    return 1;
}

int option_long (void *data, int argc, char **argv)
{
    if (argc<2 || !argv[1]) {
        gt_print("option `%s' need an integer argument\n", argv[0]);
        return -1;
    }

    errno = 0;
    char *end;
    long val = strtol(argv[1], &end, 0);

    if (errno || argv[1]==end) {
        gt_print("argument `%s' is not a valid integer\n", argv[1]);
        return -1;
    }

    byte_cpy(data, &val, sizeof(val));

    return 1;
}

int option_is_set (struct option *opts, const char *name)
{
    for (int k=0; opts[k].name; k++) {
        if (!str_cmp(opts[k].name, name))
            return opts[k].set;
    }

    return 0;
}

int option_option (void *data, int argc, char **argv)
{
    struct option *opts = (struct option *)data;

    for (int k=0; opts[k].name; k++)
        opts[k].set = 0;

    for (int i=1; i<argc; i++) {
        int found = 0;

        for (int k=0; opts[k].name; k++) {
            if (str_cmp(opts[k].name, argv[i]))
                continue;

            if (opts[k].set) {
                gt_print("option `%s' is already set\n", opts[k].name);
                return -1;
            }

            int ret = opts[k].call(opts[k].data, argc-i, &argv[i]);

            if (ret<0)
                return -1;

            opts[k].set = 1;

            i += ret;
            found = 1;
            break;
        }

        if (!found)
            return i-1;
    }

    return argc;
}

static int option_usage (struct option *opts, int slen)
{
    int len = slen;

    for (int k=0; opts[k].name; k++) {
        if (len>60) {
            gt_print("\n%*s", (int)slen, "");
            len = slen;
        }

        len += gt_print(" [%s", opts[k].name);

        if (opts[k].call!=option_flag) {
            if (opts[k].call==option_option) {
                len += option_usage((struct option *)opts[k].data, len);
            } else {
                len += gt_print(" ARG");
            }
        }

        len += gt_print("]");
    }

    return len;
}

int option (struct option *opts, int argc, char **argv)
{
    int ret = option_option(opts, argc, argv);

    if (ret==argc)
        return 0;

    if (ret<0 || ret+1>=argc)
        return 1;

    gt_print("option `%s' is unknown\n", argv[ret+1]);

    int slen = gt_print("usage: %s", argv[0]);

    if (slen>40)
        slen = 12;

    option_usage(opts, slen);

    printf("\n");

    return 1;
}
