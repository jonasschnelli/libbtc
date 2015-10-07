ACLOCAL_AMFLAGS = -I build-aux/m4

include_HEADERS = include/libbtc.h
lib_LTLIBRARIES = src/libbtc.la

lib_libbtc_la_SOURCES = \
	src/aes.c

lib_libbtc_la_LDFLAGS = \
	-version-info 1:0:0 \
	-no-undefined
lib_libbtc_la_CFLAGS = -I$(top_srcdir)/include
