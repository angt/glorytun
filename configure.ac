AC_PREREQ([2.68])
AC_INIT([glorytun], [0.0.1],
        [https://github.com/angt/glorytun/issues],
        [glorytun],
        [https://github.com/angt/glorytun])
AM_INIT_AUTOMAKE([1.9 -Wall -Werror foreign tar-ustar])
AM_DEP_TRACK
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([common.h])
AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
AC_SEARCH_LIBS(clock_gettime, [rt],
  [AC_DEFINE(HAVE_CLOCK_GETTIME,[1],[define if you have clock_gettime()])])
PKG_CHECK_MODULES([libsodium], [libsodium >= 1.0.4],
  [CFLAGS="$CFLAGS $libsodium_CFLAGS"], [echo "not found"])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
