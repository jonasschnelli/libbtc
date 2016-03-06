/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <btc/block.h>

#include <btc/cstr.h>
#include <btc/ecc_key.h>
#include "utils.h"

struct blockheadertest {
    char hexheader[160];
    char hexhash[64];
};

static const struct blockheadertest block_header_tests[] =
        {
                {"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c", "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"}
        };

void test_block_header()
{
    int outlen;
    cstring* serialized = cstr_new_sz(80);
    char hexbuf[160];
    unsigned int i;
    for (i = 0; i < (sizeof(block_header_tests) / sizeof(block_header_tests[0])); i++) {

        const struct blockheadertest* test = &block_header_tests[i];
        uint8_t header_data[80];
        uint8_t hash_data[32];

        utils_hex_to_bin(test->hexheader, header_data, 160, &outlen);
        utils_hex_to_bin(test->hexhash, hash_data, 32, &outlen);

        btc_block_header* header = btc_block_header_new();
        btc_block_header_deserialize(header_data, 80, header);

        // Check the copies are the same
        btc_block_header* header_copy = btc_block_header_new();
        btc_block_header_copy(header_copy, header);
        assert(memcpy(header_copy, header, sizeof(header_copy)));

        // Check the serialized form matches
        btc_block_header_serialize(serialized, header);
        utils_bin_to_hex((unsigned char*) serialized->str, serialized->len, hexbuf);
        assert(memcmp(hexbuf, test->hexheader, 160) == 0);

        // Check the block hash
        uint8_t blockhash[32];
        btc_block_header_hash(header, blockhash);

        utils_bin_to_hex(blockhash, 32, hexbuf);
        utils_reverse_hex(hexbuf, 64);
        assert(memcmp(hexbuf, test->hexhash, 64) == 0);

        btc_block_header_free(header);
        btc_block_header_free(header_copy);
    }
    cstr_free(serialized, true);
}