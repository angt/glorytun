ACLOCAL_AMFLAGS = -I m4 --install

bin_PROGRAMS = glorytun

glorytun_CFLAGS = $(libsodium_CFLAGS)
glorytun_LDADD = $(libsodium_LIBS)
glorytun_SOURCES = \
    src/common.h \
    src/common.c \
    src/ip.h \
    src/str.h \
    src/main.c \
    src/option.c \
    src/option.h \
    src/tun.c \
    src/tun.h \
    src/db.c \
    src/db.h

glorytun_CFLAGS  += -I$(srcdir)/mud
glorytun_SOURCES += \
    mud/mud.h \
    mud/mud.c

EXTRA_DIST = \
    LICENSE \
    README.md \
    VERSION \
    autogen.sh \
    version.sh
