#include "common.h"
#include "argz.h"

volatile sig_atomic_t gt_alarm;
volatile sig_atomic_t gt_reload;
volatile sig_atomic_t gt_quit;

static void
gt_sa_handler(int sig)
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
    struct sigaction sa = {0};

    sa.sa_handler = gt_sa_handler;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

int gt_list    (int, char **, void *);
int gt_show    (int, char **, void *);
int gt_bench   (int, char **, void *);
int gt_bind    (int, char **, void *);
int gt_set     (int, char **, void *);
int gt_keygen  (int, char **, void *);
int gt_path    (int, char **, void *);
int gt_version (int, char **, void *);

int
main(int argc, char **argv)
{
    gt_set_signal();

    struct argz z[] = {
        {"list",    "List all tunnels",          gt_list,    .grp = 1},
        {"show",    "Show tunnel information",   gt_show,    .grp = 1},
        {"bench",   "Start a crypto bench",      gt_bench,   .grp = 1},
        {"bind",    "Start a new tunnel",        gt_bind,    .grp = 1},
        {"set",     "Change tunnel properties",  gt_set,     .grp = 1},
        {"keygen",  "Generate a new secret key", gt_keygen,  .grp = 1},
        {"path",    "Manage paths",              gt_path,    .grp = 1},
        {"version", "Show version",              gt_version, .grp = 1},
        {0}};

    if (argc == 1) {
        argz_print(z);
        return 0;
    }
    return argz_main(argc, argv, z);
}
