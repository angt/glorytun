ACLOCAL_AMFLAGS = -I m4 --install

bin_PROGRAMS = glorytun

glorytun_CFLAGS = $(libsodium_CFLAGS)
glorytun_LDADD = $(libsodium_LIBS)
glorytun_SOURCES = \
    argz/argz.c \
    argz/argz.h \
    mud/aegis256/aegis256.c \
    mud/aegis256/aegis256.h \
    mud/mud.c \
    mud/mud.h \
    src/bench.c \
    src/bind.c \
    src/common.c \
    src/common.h \
    src/ctl.c \
    src/ctl.h \
    src/iface.c \
    src/iface.h \
    src/ip.h \
    src/keygen.c \
    src/list.c \
    src/main.c \
    src/path.c \
    src/set.c \
    src/show.c \
    src/tun.c \
    src/tun.h \
    src/version.c

EXTRA_DIST = \
    LICENSE \
    Makefile \
    README.md \
    VERSION \
    autogen.sh \
    meson.build \
    mud/LICENSE \
    mud/README.md \
    sodium.sh \
    systemd \
    version.sh
