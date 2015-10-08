dnl require autoconf 2.68 (AS_ECHO/AS_ECHO_N)
AC_PREREQ([2.68])
AC_INIT([libbtc],[0.1],[https://github.com/jonasschnelli/libbtc/issues],[libbtc])
AC_CONFIG_HEADERS([src/libbtc-config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([no-define subdir-objects foreign])

LT_INIT

AC_ARG_ENABLE(tests,
    AS_HELP_STRING([--enable-tests],[compile tests (default is yes)]),
    [use_tests=$enableval],
    [use_tests=yes])

AC_MSG_CHECKING([for __builtin_expect])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[void myfunc() {__builtin_expect(0,0);}]])],
    [ AC_MSG_RESULT([yes]);AC_DEFINE(HAVE_BUILTIN_EXPECT,1,[Define this symbol if __builtin_expect is available]) ],
    [ AC_MSG_RESULT([no])
    ])

AC_CONFIG_FILES([Makefile])
AC_SUBST(LIBTOOL_APP_LDFLAGS)
AC_SUBST(BUILD_EXEEXT)
AM_CONDITIONAL([USE_TESTS], [test x"$use_tests" != x"no"])

AC_CONFIG_SUBDIRS([src/secp256k1])

AC_OUTPUT
