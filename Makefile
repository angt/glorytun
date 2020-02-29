NAME    := glorytun
VERSION := $(shell ./version.sh)
DIST    := $(NAME)-$(VERSION)

CC      ?= cc
prefix  ?= /usr
Q       := @

CFLAGS := -std=c11 -O2 -Wall -fstack-protector-strong

FLAGS := $(CFLAGS) $(LDFLAGS) $(CPPFLAGS)
FLAGS += -DPACKAGE_NAME=\"$(NAME)\" -DPACKAGE_VERSION=\"$(VERSION)\"

FLAGS += -I.static/$(CROSS)/libsodium-stable/src/libsodium/include
FLAGS += -L.static/$(CROSS)/libsodium-stable/src/libsodium/.libs

SRC := argz/argz.c mud/mud.c mud/aegis256/aegis256.c $(wildcard src/*.c)
HDR := argz/argz.h mud/mud.h mud/aegis256/aegis256.h $(wildcard src/*.h)

ifneq ($(CROSS),)
    X = $(CROSS)-
endif

$(NAME): $(SRC) $(HDR)
	$(Q)$(X)$(CC) $(FLAGS) -o $(NAME) $(SRC) -lsodium

$(NAME)-strip: $(NAME)
	$(Q)cp $< $@
	$(Q)$(X)strip -s $@

.PHONY: install
install: $(NAME)-strip
	@echo "$(DESTDIR)$(prefix)/bin/$(NAME)"
	$(Q)install -m 755 -d $(DESTDIR)$(prefix)/bin
	$(Q)install -m 755 $(NAME)-strip $(DESTDIR)$(prefix)/bin/$(NAME)

.PHONY: clean
clean:
	$(Q)rm -f "$(NAME)"
	$(Q)rm -f "$(DIST).tar.gz"
