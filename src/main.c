#include "common.h"
#include "str.h"

#include <stdio.h>

volatile sig_atomic_t gt_alarm;
volatile sig_atomic_t gt_reload;
volatile sig_atomic_t gt_quit;

static void
gt_quit_handler(int sig)
{
    switch (sig) {
    case SIGALRM:
        gt_alarm = 1;
        return;
    case SIGHUP:
        gt_reload = 1; /* FALLTHRU */
    default:
        gt_quit = 1;
    }
}

static void
gt_set_signal(void)
{
    struct sigaction sa = {
        .sa_flags = 0,
    };

    sigemptyset(&sa.sa_mask);

    sa.sa_handler = gt_quit_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

static int
gt_version(int argc, char **argv)
{
    printf(PACKAGE_VERSION "\n");
    return 0;
}

int
gt_show(int argc, char **argv)
{
    printf("show (todo)\n");
    return 0;
}

int
gt_key(int argc, char **argv)
{
    printf("key (todo)\n");
    return 0;
}

int gt_bind(int, char **);
int gt_path(int, char **);
int gt_keygen(int, char **);
int gt_bench(int, char **);

int
main(int argc, char **argv)
{
    gt_set_signal();

    struct {
        char *name;
        char *help;
        int (*call)(int, char **);
    } cmd[] = {
        {"show", "show all running tunnels", gt_show},
        {"bind", "start a new tunnel", gt_bind},
        {"path", "manage paths", gt_path},
        {"keygen", "generate a new secret key", gt_keygen},
        {"bench", "start a crypto bench", gt_bench},
        {"version", "show version", gt_version},
        {}};

    if (argc > 1) {
        for (int k = 0; cmd[k].name; k++) {
            if (!str_cmp(cmd[k].name, argv[1]))
                return cmd[k].call(argc - 1, argv + 1);
        }
        printf("unknown command %s\n", argv[1]);
    }

    printf("\navailable commands:\n");

    int len = 0;

    for (int k = 0; cmd[k].name; k++)
        len = MAX(len, (int)str_len(cmd[k].name, 32));

    for (int k = 0; cmd[k].name; k++)
        printf("  %-*s  %s\n", len, cmd[k].name, cmd[k].help);

    printf("\n");

    return argc != 1;
}
