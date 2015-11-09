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
        printf("option `%s' need a string argument\n", argv[0]);
        return -1;
    }

    byte_cpy(data, &argv[1], sizeof(argv[1]));

    return 1;
}

int option_long (void *data, int argc, char **argv)
{
    if (argc<2 || !argv[1]) {
        printf("option `%s' need an integer argument\n", argv[0]);
        return -1;
    }

    errno = 0;
    char *end;
    long val = strtol(argv[1], &end, 0);

    if (errno || argv[1]==end) {
        printf("argument `%s' is not a valid integer\n", argv[1]);
        return -1;
    }

    byte_cpy(data, &val, sizeof(val));

    return 1;
}

int option_option (void *data, int argc, char **argv)
{
    struct option *opts = (struct option *)data;

    for (int i=1; i<argc; i++) {
        int found = 0;

        for (int k=0; opts[k].name; k++) {
            if (str_cmp(opts[k].name, argv[i]))
                continue;

            int ret = opts[k].call(opts[k].data, argc-i, &argv[i]);

            if (ret<0)
                return -1;

            i += ret;
            found = 1;
            break;
        }

        if (!found)
            return i-1;
    }

    return argc;
}

static void option_usage (struct option *opts, char *name)
{
    char *usage = "usage: ";
    size_t slen = str_len(usage)+str_len(name);
    size_t len = slen;

    printf("%s%s", usage, name);

    if (slen>40)
        slen = 12;

    for (int k=0; opts[k].name; k++) {
        int isflag = opts[k].call==option_flag;
        size_t inc = str_len(opts[k].name)+(isflag?0:4)+4;

        if (len+inc>60) {
            printf("\n%*s", (int)slen, "");
            len = 0;
        }
        printf(" [%s%s]", opts[k].name, isflag?"":" ARG");
        len += inc;
    }

    printf("\n");
}

int option (struct option *opts, int argc, char **argv)
{
    int ret = option_option(opts, argc, argv);

    if (ret==argc)
        return 0;

    if (ret<0 || ret+1>=argc)
        return 1;

    printf("option `%s' is unknown\n", argv[ret+1]);
    option_usage(opts, argv[0]);

    return 1;
}
