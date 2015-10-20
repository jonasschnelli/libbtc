/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2015 Douglas J. Bakkumk
 * Copyright (c) 2015 Jonas Schnelli
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */


#ifndef __LIBBTC_BIP32_H__
#define __LIBBTC_BIP32_H__

#include "btc.h"

#include <stdint.h>


typedef struct {
    uint32_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    uint8_t chain_code[32];
    uint8_t private_key[32];
    uint8_t public_key[33];
} HDNode;


#define hdnode_private_ckd_prime(X, I) hdnode_private_ckd((X), ((I) | 0x80000000))


LIBBTC_API bool hdnode_public_ckd(HDNode *inout, uint32_t i);
LIBBTC_API bool hdnode_from_seed(const uint8_t *seed, int seed_len, HDNode *out);
LIBBTC_API bool hdnode_private_ckd(HDNode *inout, uint32_t i);
LIBBTC_API void hdnode_fill_public_key(HDNode *node);
LIBBTC_API void hdnode_serialize_public(const HDNode *node, char *str, int strsize);
LIBBTC_API void hdnode_serialize_private(const HDNode *node, char *str, int strsize);
LIBBTC_API bool hdnode_deserialize(const char *str, HDNode *node);

//!derive HDNode including private key from master private key
LIBBTC_API bool hd_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                    const uint8_t *chaincode);

#endif // __LIBBTC_BIP32_H__
