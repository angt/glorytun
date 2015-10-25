CC      := gcc
LDFLAGS := -Wl,-O1,--sort-common,--as-needed
CFLAGS  := -ffreestanding -Wall -Wextra

prefix  := /usr/local

ifdef temps
CFLAGS += -save-temps
endif

ifdef debug
CFLAGS += -O0 -fno-omit-frame-pointer -g
else
CFLAGS += -O3 -fomit-frame-pointer -DNDEBUG
endif

ifdef sanitize
CFLAGS += -fsanitize=$(sanitize)
endif

.PHONY: default install clean setcap

default: glorytun

install:
	install -m 755 -d $(DESTDIR)$(prefix)/bin
	install -m 755 -s glorytun $(DESTDIR)$(prefix)/bin

clean:
	@rm -f *.[ios] glorytun

setcap:
	setcap cap_net_admin+ep glorytun

glorytun: glorytun.o
glorytun.c: common-static.h
common-static.h: common.h
