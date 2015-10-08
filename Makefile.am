ACLOCAL_AMFLAGS = -I build-aux/m4

include_HEADERS = include/libbtc.h
lib_LTLIBRARIES = src/libbtc.la

src_libbtc_la_SOURCES = \
	src/aes.c

src_libbtc_la_LDFLAGS = \
	-version-info 1:0:0 \
	-no-undefined
src_libbtc_la_CFLAGS = -I$(top_srcdir)/include

if USE_TESTS
noinst_PROGRAMS = tests
tests_SOURCES = test/unittester.c
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
TESTS = tests
endif