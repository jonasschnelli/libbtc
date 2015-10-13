DIST_SUBDIRS = src/secp256k1
ACLOCAL_AMFLAGS = -I build-aux/m4

LIBSECP256K1=src/secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard src/secp256k1/src/*) $(wildcard src/secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

include_HEADERS = include/libbtc.h
lib_LTLIBRARIES = src/libbtc.la

noinst_HEADERS = \
	src/sha2.h \
	src/utils.h \
	src/base58.h \
	src/ripemd160.h \
	src/bip32.h \
	src/ecc_wrapper.h \
	src/random.h \
	src/vector.h \
	src/buffer.h

src_libbtc_la_SOURCES = \
	src/sha2.c \
	src/utils.c \
	src/base58.c \
	src/ripemd160.c \
	src/bip32.c \
	src/ecc_libsecp256k1.c \
	src/random.c \
	src/vector.c \
	src/buffer.c

src_libbtc_la_LDFLAGS = \
	-version-info 1:0:0 \
	-no-undefined
src_libbtc_la_CFLAGS = -I$(top_srcdir)/include
src_libbtc_la_LIBADD = $(LIBSECP256K1)

if USE_TESTS
noinst_PROGRAMS = tests
tests_LDADD = src/libbtc.la
tests_SOURCES = \
	test/utest.h \
	test/unittester.c \
	test/sha2_tests.c \
	test/base58check_tests.c \
	test/bip32_tests.c \
	test/random_tests.c \
	test/ecc_tests.c \
	test/vector_tests.c

tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
TESTS = tests
endif