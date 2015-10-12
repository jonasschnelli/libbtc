/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ecc_wrapper.h"
#include "flags.h"
#include "random.h"
#include "utest.h"
#include "utils.h"

void test_ecc()
{
    unsigned char r_buf[32];
    memset(r_buf, 0, 32);
    random_init();

    while(ecc_verify_privatekey(r_buf) == 0)
    {
        random_bytes(r_buf, 32, 0);
    }

    memset(r_buf, 0xFF, 32);
    u_assert_int_eq(ecc_verify_privatekey(r_buf), 0); //secp256k1 overflow

    uint8_t sig[64], pub_key33[33], pub_key65[65], msg[256];
    memcpy(pub_key33,
           utils_hex_to_uint8("024054fd18aeb277aeedea01d3f3986ff4e5be18092a04339dcf4e524e2c0a0974"),
           33);
    memcpy(pub_key65,
           utils_hex_to_uint8("044054fd18aeb277aeedea01d3f3986ff4e5be18092a04339dcf4e524e2c0a09746c7083ed2097011b1223a17a644e81f59aa3de22dac119fd980b36a8ff29a244"),
           65);
}