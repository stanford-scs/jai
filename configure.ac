AC_INIT([jai], [0.2-dev],
   [https://github.com/stanford-scs/jai/issues
   or https://www.scs.stanford.edu/~dm/addr/],,
   [https://jai.scs.stanford.edu/])
AM_INIT_AUTOMAKE([foreign -Wall -Werror serial-tests])
AC_CONFIG_HEADERS([config.h])

: ${CXXLANG=-std=gnu++23}

AC_PROG_CXX

# Require C++23
CXXFLAGS="$CXXFLAGS $CXXLANG"
AC_LANG_PUSH([C++])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([], [])],
  [],
  [AC_MSG_ERROR([a C++23 compiler is required])])
AC_LANG_POP([C++])

PKG_CHECK_MODULES([MOUNT], [mount])
PKG_CHECK_MODULES([LIBACL], [libacl])

AC_PATH_PROG([PATH_BASH], [bash], [/bin/bash])
AC_DEFINE_UNQUOTED([PATH_BASH], ["$PATH_BASH"], [Path to bash])

# --with-untrusted-user=USER (default: auto-detect from password file or "jai")
# Note: this sets the compiled-in default username.  At runtime,
# init_credentials() validates the user exists with the correct GECOS
# field, so a mismatch between build and runtime environments is safe.
AC_ARG_WITH([untrusted-user],
  [AS_HELP_STRING([--with-untrusted-user=USER],
    [name of untrusted sandbox user (default: autodetect or jai)])],
  [UNTRUSTED_USER="$withval"],
  [UNTRUSTED_USER=""])

AS_IF([test -z "$UNTRUSTED_USER"], [
  UNTRUSTED_USER=$(getent passwd 2>/dev/null | \
    awk -F: '$3 != 0 && $5 == "JAI sandbox untrusted user" { print $1; exit }')
  AS_IF([test -z "$UNTRUSTED_USER"], [
    AS_IF([getent passwd jai > /dev/null],
      [UNTRUSTED_USER=_jai], [UNTRUSTED_USER=jai])
  ])
])
AC_MSG_NOTICE([untrusted user: $UNTRUSTED_USER])
AC_SUBST([UNTRUSTED_USER])
AC_DEFINE_UNQUOTED([UNTRUSTED_USER], ["$UNTRUSTED_USER"],
  [Username for the sandboxed untrusted user])

TEST_ABS_TOP_BUILDDIR=`pwd -P`
TEST_ABS_TOP_SRCDIR=`cd "$srcdir" && pwd -P`
AC_SUBST([TEST_ABS_TOP_BUILDDIR])
AC_SUBST([TEST_ABS_TOP_SRCDIR])

AC_CONFIG_FILES([Makefile tests/Makefile jai.conf tests/common.sh tests/setup-setuid.sh])
AC_CONFIG_COMMANDS([test-scripts], [chmod +x tests/common.sh tests/setup-setuid.sh])
AC_OUTPUT
