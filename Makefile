NAME     = glorytun
VERSION != ./version.sh
DIST     = $(NAME)-$(VERSION)

CC       = cc
CFLAGS   = -std=c99 -O2 -Wall -fstack-protector-strong
CPPFLAGS = -I.sodium/$(X)build/src/libsodium/include
LDFLAGS  = -L.sodium/$(X)build/src/libsodium/.libs
LDLIBS   = -lsodium
prefix   = /usr/local
PREFIX   = $(prefix)

$(NAME):
	$(X)$(CC) $(EXTRA) \
	    $(CFLAGS) \
	    $(CPPFLAGS) \
	    $(LDFLAGS) \
	    -DPACKAGE_NAME=\"$(NAME)\" \
	    -DPACKAGE_VERSION=\"$(VERSION)\" \
	    argz/argz.c \
	    mud/aegis256/aegis256.c \
	    mud/mud.c \
	    src/argz.c \
	    src/bench.c \
	    src/bind.c \
	    src/common.c \
	    src/ctl.c \
	    src/iface.c \
	    src/keygen.c \
	    src/list.c \
	    src/main.c \
	    src/path.c \
	    src/set.c \
	    src/show.c \
	    src/tun.c \
	    src/version.c \
	    -o $(NAME) \
	    $(LDLIBS)

install: $(NAME)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mv -f $(NAME) $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(NAME)

clean:
	rm -f $(NAME)

.PHONY: $(NAME) install uninstall clean
