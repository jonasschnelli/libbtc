/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "eckey.h"
#include "utils.h"

void test_eckey()
{
    btc_key* key = btc_privkey_new();


    btc_pubkey *pubkey = btc_pubkey_new();
    btc_pubkey_from_key(key, pubkey);

    unsigned int i;
    for(i = 33; i < BTC_ECKEY_UNCOMPRESSED_LENGTH; i++)
        assert(pubkey->pubkey[i] == 0);

    uint8_t *hash = utils_hex_to_uint8((const char *)"26db47a48a10b9b0b697b793f5c0231aa35fe192c9d063d7b03a55e3c302850a");

    unsigned char sig[100];
    int outlen = 0;
    btc_key_sign_hash(key, hash, sig, &outlen);

    btc_pubkey_verify_sig(pubkey, hash, sig, outlen);

    btc_pubkey_free(pubkey);
    btc_privkey_free(key);
}