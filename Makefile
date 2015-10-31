CC      := gcc
LDFLAGS := -Wl,-O1,--sort-common,--as-needed
CFLAGS  := -ffreestanding -Wall -Wextra
LDLIBS  := -lsodium

prefix  := /usr/local

ifdef temps
CFLAGS += -save-temps
endif

ifdef debug
CFLAGS += -O0 -fno-omit-frame-pointer
FLAGS  += -g
else
CFLAGS += -O3 -fomit-frame-pointer -DNDEBUG
endif

ifdef sanitize
FLAGS += -fsanitize=$(sanitize)
endif

CFLAGS  += $(FLAGS)
LDFLAGS += $(FLAGS)

.PHONY: default install clean setcap

default: glorytun

install:
	install -m 755 -d $(DESTDIR)$(prefix)/bin
	install -m 755 -s glorytun $(DESTDIR)$(prefix)/bin

clean:
	@rm -f *.[ios] glorytun

setcap:
	setcap cap_net_admin+ep glorytun

glorytun.o: common.h common-static.h
