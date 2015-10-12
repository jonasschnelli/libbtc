dnl require autoconf 2.68 (AS_ECHO/AS_ECHO_N)
AC_PREREQ([2.68])
AC_INIT([libbtc],[0.1],[https://github.com/jonasschnelli/libbtc/issues],[libbtc])
AC_CONFIG_HEADERS([src/libbtc-config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CANONICAL_HOST
AH_TOP([#ifndef LIBBTC_CONFIG_H])
AH_TOP([#define LIBBTC_CONFIG_H])
AH_BOTTOM([#endif /*LIBBTC_CONFIG_H*/])
AM_INIT_AUTOMAKE([no-define subdir-objects foreign])

LT_INIT

# Enable debug
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [use debug compiler flags and macros (default is no)])],
    [enable_debug=$enableval],
    [enable_debug=no])

if test "x$enable_debug" = xyes; then
    CFLAGS="$CFLAGS -g3 -O0 -DDEBUG"
    CXXFLAGS="$CXXFLAGS -g3 -O0 -DDEBUG"
		AC_DEFINE_UNQUOTED([ENABLE_DEBUG],[1],[Define to 1 to enable debung output])
fi

AC_ARG_ENABLE(tests,
    AS_HELP_STRING([--enable-tests],[compile tests (default is yes)]),
    [use_tests=$enableval],
    [use_tests=yes])

AC_MSG_CHECKING([for __builtin_expect])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[void myfunc() {__builtin_expect(0,0);}]])],
    [ AC_MSG_RESULT([yes]);AC_DEFINE(HAVE_BUILTIN_EXPECT,1,[Define this symbol if __builtin_expect is available]) ],
    [ AC_MSG_RESULT([no])
    ])

m4_include(m4/macros/with.m4)
ARG_WITH_SET([random-device],      [/dev/urandom], [set the device to read random data from])
if test "x$random_device" = x"/dev/urandom"; then
		AC_DEFINE_UNQUOTED([FILE_RANDOM],[1],[Define to 1 to enable random retrieving over filehandle])
    AC_DEFINE([RANDOM_DEVICE],["/dev/urandom"],[Define to set random file handle])
fi
if test "x$random_device" = x"/dev/random"; then
		AC_DEFINE_UNQUOTED([FILE_RANDOM],[1],[Define to 1 to enable /dev/random as random device])
    AC_DEFINE([RANDOM_DEVICE],["/dev/random"],[Define to set random file handle])
fi

AC_CONFIG_FILES([Makefile])
AC_SUBST(LIBTOOL_APP_LDFLAGS)
AC_SUBST(BUILD_EXEEXT)
AM_CONDITIONAL([USE_TESTS], [test x"$use_tests" != x"no"])

AC_CONFIG_SUBDIRS([src/secp256k1])

AC_OUTPUT
