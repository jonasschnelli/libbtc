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

#ifndef __LIBBTC_ECC_H__
#define __LIBBTC_ECC_H__

#include "btc.h"

#include <stdint.h>

//!init static ecc context
LIBBTC_API void ecc_start(void);

//!destroys the static ecc context
LIBBTC_API void ecc_stop(void);

//!get public key from given private key
LIBBTC_API void ecc_get_pubkey(const uint8_t *private_key, uint8_t *public_key,
                           int public_key_len, int compressed);

//!get uncompressed public key from given private key
void ecc_get_public_key65(const uint8_t *private_key, uint8_t *public_key);

//!get compressed public key from given private key
void ecc_get_public_key33(const uint8_t *private_key, uint8_t *public_key);

//!ec mul tweak on given private key
LIBBTC_API bool ecc_private_key_tweak_add(uint8_t *private_key, const uint8_t *tweak);

//!ec mul tweak on given public key
LIBBTC_API bool ecc_public_key_tweak_add(uint8_t *public_key_inout, const uint8_t *tweak);

//!verifies a given 32byte key
LIBBTC_API bool ecc_verify_privatekey(const uint8_t *private_key);

//!verifies a given public key (compressed[33] or uncompressed[65] bytes)
LIBBTC_API bool ecc_verify_pubkey(const uint8_t *public_key, int compressed);

LIBBTC_API bool ecc_sign(const uint8_t *private_key, const uint8_t *hash, unsigned char *sigder, size_t *outlen);
LIBBTC_API bool ecc_verify_sig(const uint8_t *public_key, int compressed, const uint8_t *hash, unsigned char *sigder, size_t siglen);

#endif //__LIBBTC_ECC_H__
