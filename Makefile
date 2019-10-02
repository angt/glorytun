NAME    := glorytun
VERSION := $(shell ./version.sh)
DIST    := $(NAME)-$(VERSION)

DESTDIR ?=
CC      ?= gcc
INSTALL ?= install
prefix  ?= /usr
CFLAGS  ?= -std=c11 -O2 -Wall -fstack-protector-strong

FLAGS := $(CFLAGS) $(LDFLAGS) $(CPPFLAGS)
FLAGS += -DPACKAGE_NAME=\"$(NAME)\" -DPACKAGE_VERSION=\"$(VERSION)\"

FLAGS += -I.static/$(CROSS)/libsodium-stable/src/libsodium/include
FLAGS += -L.static/$(CROSS)/libsodium-stable/src/libsodium/.libs

SRC := argz/argz.c mud/mud.c mud/aegis256/aegis256.c $(wildcard src/*.c)

.PHONY: $(NAME)
$(NAME):
	@echo "Building $(NAME)"
	@$(CC) $(FLAGS) -o $(NAME) $(SRC) -lsodium

.PHONY: install
install: $(NAME)
	@echo "Installing $(NAME)"
	@$(INSTALL) -m 755 -d $(DESTDIR)$(prefix)/bin
	@$(INSTALL) -m 755 -s $(NAME) $(DESTDIR)$(prefix)/bin

.PHONY: dist
dist:
	@echo "Building $(DIST).tar.gz"
	@(git --git-dir=.git ls-files --recurse-submodules -- ':!:.*' ':!:**/.*' && echo VERSION) | ( \
	    tar zcf $(DIST).tar.gz -T- --transform 's:^:$(DIST)/:' || \
	    tar zcf $(DIST).tar.gz -T- -s ':^:$(DIST)/:' ) 2>/dev/null
