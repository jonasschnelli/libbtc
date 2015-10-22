/*

 The MIT License (MIT)

 Copyright (c) 2015 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <btc/ecc_key.h>

#include "utils.h"

void test_eckey()
{
    btc_key key;
    btc_privkey_init(&key);
    assert(btc_privkey_is_valid(&key) == 0);
    btc_privkey_gen(&key);
    assert(btc_privkey_is_valid(&key) == 1);

    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);
    assert(btc_pubkey_is_valid(&pubkey) == 0);
    btc_pubkey_from_key(&key, &pubkey);
    assert(btc_pubkey_is_valid(&pubkey) == 1);

    unsigned int i;
    for (i = 33; i < BTC_ECKEY_UNCOMPRESSED_LENGTH; i++)
        assert(pubkey.pubkey[i] == 0);

    uint8_t* hash = utils_hex_to_uint8((const char*)"26db47a48a10b9b0b697b793f5c0231aa35fe192c9d063d7b03a55e3c302850a");
    unsigned char sig[74];
    size_t outlen = 74;
    btc_key_sign_hash(&key, hash, sig, &outlen);

    btc_pubkey_verify_sig(&pubkey, hash, sig, outlen);
}
