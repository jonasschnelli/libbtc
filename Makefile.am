ACLOCAL_AMFLAGS = -I build-aux/m4
.PHONY: gen
.INTERMEDIATE: $(GENBIN)

DIST_SUBDIRS = src/secp256k1
DIST_SUBDIRS += src/logdb

LIBSECP256K1=src/secp256k1/libsecp256k1.la
LIBLOGDB=src/logdb/liblogdb.la

$(LIBSECP256K1): $(wildcard src/secp256k1/src/*) $(wildcard src/secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
	
$(LIBLOGDB): $(wildcard src/logdb/src/*) $(wildcard src/logdb/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

lib_LTLIBRARIES = libbtc.la
include_HEADERS = include/btc/btc.h \
	include/btc/tx.h \
	include/btc/block.h \
	include/btc/base58.h \
	include/btc/bip32.h \
	include/btc/ecc_key.h \
	include/btc/ecc.h \
	include/btc/chain.h \
	include/btc/hash.h \
	include/btc/vector.h \
	include/btc/script.h \
	include/btc/aes.h \
	include/btc/random.h \
	include/btc/tool.h

noinst_HEADERS = \
	src/ripemd160.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libbtc.pc

libbtc_la_SOURCES = \
	src/block.c \
	src/base58.c \
	src/ripemd160.c \
	src/bip32.c \
	src/ecc_libsecp256k1.c \
	src/random.c \
	src/vector.c \
	src/tx.c \
	src/script.c \
	src/ecc_key.c \
	src/aes.c \
	src/toolfunc.c

libbtc_la_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/logdb/include
libbtc_la_LIBADD = $(LIBSECP256K1) $(LIBLOGDB)

if USE_TESTS
noinst_PROGRAMS = tests
tests_LDADD = libbtc.la
tests_SOURCES = \
	test/utest.h \
	test/unittester.c \
	test/hash_tests.c \
	test/block_tests.c \
	test/base58check_tests.c \
	test/bip32_tests.c \
	test/random_tests.c \
	test/ecc_tests.c \
	test/vector_tests.c \
	test/tx_tests.c \
	test/eckey_tests.c \
	test/aes_tests.c

tests_CFLAGS = $(libbtc_la_CFLAGS)
tests_CPPFLAGS = -I$(top_srcdir)/src
tests_LDFLAGS = -static
TESTS = tests
endif

if WITH_WALLET
include_HEADERS += \
	include/btc/wallet.h

libbtc_la_SOURCES += \
	src/wallet.c

if USE_TESTS
tests_SOURCES += \
	test/wallet_tests.c
endif
endif

if WITH_TOOLS
if USE_TESTS
tests_SOURCES += \
	test/tool_tests.c
endif
instdir=$(prefix)/bin
inst_PROGRAMS = bitcointool
bitcointool_LDADD = libbtc.la
bitcointool_SOURCES = \
    src/bitcointool.c
bitcointool_CFLAGS = $(libbtc_la_CFLAGS)
bitcointool_CPPFLAGS = -I$(top_srcdir)/src
bitcointool_LDFLAGS = -static
endif

clean-local:
	-$(MAKE) -C src/secp256k1 clean
	-$(MAKE) -C src/logdb clean
