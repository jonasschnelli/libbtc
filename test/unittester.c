/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libbtc-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utest.h"

#ifdef HAVE_BUILTIN_EXPECT
#define EXPECT(x,c) __builtin_expect((x),(c))
#else
#define EXPECT(x,c) (x)
#endif

#define TEST_FAILURE(msg) do { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
    abort(); \
} while(0)

#define CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE("test condition failed: " #cond); \
    } \
} while(0)

extern void test_random();
extern void test_sha_256();
extern void test_sha_512();
extern void test_sha_hmac();
extern void test_base58check();
extern void test_bip32();
extern void test_ecc();
extern void test_vector();
extern void test_cstr();
extern void test_buffer();
extern void test_utils();
extern void test_serialize();
extern void test_tx_serialization();
extern void test_tx_sighash();
extern void test_script_parse();
extern void test_eckey();


extern void ecc_start();
extern void ecc_stop();

int U_TESTS_RUN = 0;
int U_TESTS_FAIL = 0;

int main()
{
    ecc_start();

    test_random();
    test_sha_256();
    test_sha_512();
    test_sha_hmac();
    test_base58check();
    test_utils();

    test_bip32();
    test_ecc();
    test_vector();
    test_cstr();
    test_buffer();
    test_serialize();
    test_tx_serialization();
    test_tx_sighash();
    test_script_parse();

    test_eckey();

    ecc_stop();
	return 0;
}
