ACLOCAL_AMFLAGS = -I m4 --install

bin_PROGRAMS = glorytun glorytunctl

glorytun_CFLAGS = $(libsodium_CFLAGS)
glorytun_LDADD = $(libsodium_LIBS)
glorytun_SOURCES = \
    src/common.h \
    src/common.c \
    src/ip.h \
    src/str.h \
    src/ctl.c \
    src/ctl.h \
    src/main.c \
    src/option.c \
    src/option.h \
    src/tun.c \
    src/tun.h \
    src/iface.c \
    src/iface.h \
    mud/mud.h \
    mud/mud.c

glorytunctl_CFLAGS =
glorytunctl_LDADD =
glorytunctl_SOURCES = \
    src/common.h \
    src/common.c \
    src/str.h \
    src/ctl.c \
    src/ctl.h \
    src/mainctl.c \
    src/option.c \
    src/option.h

EXTRA_DIST = \
    LICENSE \
    README.md \
    VERSION \
    systemd \
    mud/LICENSE \
    mud/README.md \
    meson.build \
    autogen.sh \
    version.sh
