ACLOCAL_AMFLAGS = -I build-aux/m4
.PHONY: gen
.INTERMEDIATE: $(GENBIN)

DIST_SUBDIRS = src/secp256k1

LIBSECP256K1=src/secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard src/secp256k1/src/*) $(wildcard src/secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

lib_LTLIBRARIES = libbtc.la
include_HEADERS = include/btc/btc.h \
	include/btc/tx.h \
	include/btc/base58.h \
	include/btc/bip32.h \
	include/btc/ecc_key.h \
	include/btc/ecc.h

noinst_HEADERS = \
	src/sha2.h \
	src/utils.h \
	src/ripemd160.h \
	src/random.h \
	src/vector.h \
	src/buffer.h \
	src/cstr.h \
	src/serialize.h \
	src/script.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libbtc.pc

libbtc_la_SOURCES = \
	src/sha2.c \
	src/utils.c \
	src/base58.c \
	src/ripemd160.c \
	src/bip32.c \
	src/ecc_libsecp256k1.c \
	src/random.c \
	src/vector.c \
	src/buffer.c \
	src/cstr.c \
	src/serialize.c \
	src/tx.c \
	src/script.c \
	src/ecc_key.c

libbtc_la_LDFLAGS = \
	-version-info 1:0:0 \
	-no-undefined
libbtc_la_CFLAGS = -I$(top_srcdir)/include
libbtc_la_LIBADD = $(LIBSECP256K1)

if USE_TESTS
noinst_PROGRAMS = tests
tests_LDADD = libbtc.la
tests_SOURCES = \
	test/utest.h \
	test/unittester.c \
	test/sha2_tests.c \
	test/base58check_tests.c \
	test/bip32_tests.c \
	test/random_tests.c \
	test/ecc_tests.c \
	test/vector_tests.c \
	test/cstr_tests.c \
	test/buffer_tests.c \
	test/utils_tests.c \
	test/serialize_tests.c \
	test/tx_tests.c \
	test/eckey_tests.c

tests_CFLAGS = -I$(top_srcdir)/include
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
TESTS = tests
endif