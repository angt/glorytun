bin_PROGRAMS = glorytun

glorytun_CFLAGS = $(libsodium_CFLAGS)
glorytun_LDADD = $(libsodium_LIBS)
glorytun_SOURCES = \
    src/common.h \
    src/common-static.h \
    src/common.c \
    src/ip-static.h \
    src/main.c \
    src/option.c \
    src/option.h \
    src/tun.c \
    src/tun.h

EXTRA_DIST = \
	README.md \
	autogen.sh \
	version.sh
