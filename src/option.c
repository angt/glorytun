#include "common.h"

#include "option.h"
#include "str.h"

int option_str (void *data, int argc, char **argv)
{
    if (argc<2 || str_empty(argv[1])) {
        gt_print("option `%s' need a string argument\n", argv[0]);
        return -1;
    }

    memcpy(data, &argv[1], sizeof(argv[1]));

    return 1;
}

int option_long (void *data, int argc, char **argv)
{
    if (argc<2 || str_empty(argv[1])) {
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

    memcpy(data, &val, sizeof(val));

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
    if (!data)
        return 0;

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
    if (!opts)
        return 0;

    int len = 0;

    for (int k=0; opts[k].name; k++) {
        if (len>40) {
            gt_print("\n%*s", slen, "");
            len = 0;
        }

        len += gt_print(" [%s", opts[k].name);

        if (opts[k].call==option_option) {
            len += option_usage((struct option *)opts[k].data, slen+len);
        } else {
            len += gt_print(" ARG");
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

    if (slen>40) {
        slen = 12;
        gt_print("\n%*s", slen, "");
    }

    option_usage(opts, slen);
    gt_print("\n");

    return 1;
}
