AC_PREREQ([2.69])
AC_INIT([glorytun], [0.0.1],
        [https://github.com/angt/glorytun/issues],
        [glorytun],
        [https://github.com/angt/glorytun])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([common.h])
AC_PROG_CC_C99
AC_CHECK_HEADERS([arpa/inet.h netdb.h stdint.h stdlib.h sys/ioctl.h sys/socket.h unistd.h])
AC_C_INLINE
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_FUNC_MALLOC
AC_CHECK_FUNCS([socket strtol])
PKG_CHECK_MODULES([libsodium], [libsodium >= 1.0.4])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
