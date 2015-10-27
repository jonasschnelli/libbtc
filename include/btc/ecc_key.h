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

#ifndef __LIBBTC_ECC_KEY_H__
#define __LIBBTC_ECC_KEY_H__

#include "btc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

typedef struct btc_key_
{
    uint8_t privkey[BTC_ECKEY_PKEY_LENGTH];
} btc_key;

typedef struct btc_pubkey_
{
    btc_bool compressed;
    uint8_t pubkey[BTC_ECKEY_UNCOMPRESSED_LENGTH];
} btc_pubkey;

LIBBTC_API void btc_privkey_init(btc_key* privkey);
LIBBTC_API btc_bool btc_privkey_is_valid(btc_key* privkey);
LIBBTC_API void btc_privkey_cleanse(btc_key* privkey);
LIBBTC_API void btc_privkey_gen(btc_key* privkey);
LIBBTC_API btc_bool btc_privkey_verify_pubkey(btc_key* privkey, btc_pubkey* pubkey);

LIBBTC_API void btc_pubkey_init(btc_pubkey* pubkey);
LIBBTC_API btc_bool btc_pubkey_is_valid(btc_pubkey* pubkey);
LIBBTC_API void btc_pubkey_cleanse(btc_pubkey* pubkey);
LIBBTC_API void btc_pubkey_from_key(btc_key* privkey, btc_pubkey* pubkey_inout);
LIBBTC_API void btc_pubkey_get_hash160(const btc_pubkey* pubkey, uint8_t *hash160);

//sign a 32byte message/hash and returns a DER encoded signature (through *sigout)
LIBBTC_API btc_bool btc_key_sign_hash(const btc_key* privkey, const uint8_t* hash, unsigned char* sigout, size_t* outlen);

//verifies a DER encoded signature with given pubkey and return true if valid
LIBBTC_API btc_bool btc_pubkey_verify_sig(const btc_pubkey* pubkey, const uint8_t* hash, unsigned char* sigder, int len);

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_ECC_KEY_H__
