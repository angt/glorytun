AC_PREREQ([2.65])
AC_INIT([glorytun], [0.0.3], [https://github.com/angt/glorytun/issues],
        [glorytun], [https://github.com/angt/glorytun])
AC_CONFIG_SRCDIR([src/common.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.9 -Wall -Werror foreign tar-ustar subdir-objects])
AM_DEP_TRACK
AM_SILENT_RULES([yes])
AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
AC_SEARCH_LIBS([getaddrinfo], [resolv nsl])
AC_SEARCH_LIBS([socket], [socket])
PKG_CHECK_MODULES([libsodium], [libsodium >= 1.0.4])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
