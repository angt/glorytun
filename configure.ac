AC_PREREQ([2.65])
AC_INIT([glorytun],
        [m4_esyscmd([./version.sh])],
        [https://github.com/angt/glorytun/issues],
        [glorytun],
        [https://github.com/angt/glorytun])
AC_DEFINE_UNQUOTED([VERSION_MAJOR], [m4_esyscmd([./version.sh major])])
AC_CONFIG_SRCDIR([src/common.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.9 -Wall -Werror foreign tar-ustar subdir-objects])
AM_DEP_TRACK
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O
AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
AC_SEARCH_LIBS([getaddrinfo], [resolv nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_FUNCS([clock_gettime])
PKG_CHECK_MODULES([libsodium], [libsodium >= 1.0.4])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
