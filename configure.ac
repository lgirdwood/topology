
AC_PREREQ(2.63)

AC_INIT([socfw], [0.1])
AC_CONFIG_SRCDIR([src/socfw.c])
AC_CONFIG_MACRO_DIR([m4])
#AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability])

# Initialize maintainer mode
AM_MAINTAINER_MODE([enable])

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_GCC_TRADITIONAL
AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_C_O

AC_CHECK_PROGS([M4], gm4 m4, no)
if test "x$M4" = xno ; then
   AC_MSG_ERROR([m4 missing])
fi

AC_HEADER_STDC

AC_C_CONST
AC_C_BIGENDIAN
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_TYPE_UID_T

# Linux kernel directory
AC_ARG_WITH(
        [linux-dir],
        AS_HELP_STRING([--with-linux-dir],[linux source code directory]),
        [LINUX_DIR=$withval], [LINUX_DIR="~/source/linux.git"])
AC_SUBST(LINUX_DIR)

AC_CONFIG_FILES([
Makefile
src/Makefile
])

AC_OUTPUT

echo "
---{ $PACKAGE_NAME $VERSION }---

prefix:                        ${prefix}
Compiler:                      ${CC}
CFLAGS:                        ${CFLAGS}
LIBS:                          ${LIBS}
Linux directory:               ${LINUX_DIR}
"
