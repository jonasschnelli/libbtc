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

#include "btc/ecc_key.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "btc/ecc.h"
#include "btc/hash.h"
#include "btc/random.h"

#include "ripemd160.h"
#include "utils.h"


void btc_privkey_init(btc_key* privkey)
{
    memset(&privkey->privkey, 0, BTC_ECKEY_PKEY_LENGTH);
}


btc_bool btc_privkey_is_valid(btc_key* privkey)
{
    return btc_ecc_verify_privatekey(privkey->privkey);
}


void btc_privkey_cleanse(btc_key* privkey)
{
    memset(&privkey->privkey, 0, BTC_ECKEY_PKEY_LENGTH);
}


void btc_privkey_gen(btc_key* privkey)
{
    if (privkey == NULL)
        return;

    do {
        random_bytes(privkey->privkey, BTC_ECKEY_PKEY_LENGTH, 0);
    } while (btc_ecc_verify_privatekey(privkey->privkey) == 0);
}


btc_bool btc_privkey_verify_pubkey(btc_key* privkey, btc_pubkey* pubkey)
{
    uint8_t rnddata[32], hash[32];
    random_bytes(rnddata, 32, 0);
    btc_hash(rnddata, 32, hash);

    unsigned char sig[74];
    size_t siglen = 74;

    if (!btc_key_sign_hash(privkey, hash, sig, &siglen))
        return false;

    return btc_pubkey_verify_sig(pubkey, hash, sig, siglen);
}


void btc_pubkey_init(btc_pubkey* pubkey)
{
    if (pubkey == NULL)
        return;

    memset(pubkey->pubkey, 0, BTC_ECKEY_UNCOMPRESSED_LENGTH);
    pubkey->compressed = false;
}


btc_bool btc_pubkey_is_valid(btc_pubkey* pubkey)
{
    return btc_ecc_verify_pubkey(pubkey->pubkey, pubkey->compressed);
}


void btc_pubkey_cleanse(btc_pubkey* pubkey)
{
    if (pubkey == NULL)
        return;

    memset(pubkey->pubkey, 0, BTC_ECKEY_UNCOMPRESSED_LENGTH);
}


void btc_pubkey_get_hash160(const btc_pubkey* pubkey, uint8_t* hash160)
{
    uint8_t hashout[32];
    btc_hash_sngl_sha256(pubkey->pubkey, pubkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH, hashout);

    ripemd160(hashout, 32, hash160);
}


btc_bool btc_pubkey_get_hex(const btc_pubkey* pubkey, char* str, size_t *strsize)
{
    if (*strsize < BTC_ECKEY_COMPRESSED_LENGTH*2)
        return false;
    utils_bin_to_hex((unsigned char *)pubkey->pubkey, BTC_ECKEY_COMPRESSED_LENGTH, str);
    *strsize = BTC_ECKEY_COMPRESSED_LENGTH*2;
    return true;
}


void btc_pubkey_from_key(btc_key* privkey, btc_pubkey* pubkey_inout)
{
    if (pubkey_inout == NULL || privkey == NULL)
        return;

    size_t in_out_len = BTC_ECKEY_COMPRESSED_LENGTH;

    btc_ecc_get_pubkey(privkey->privkey, pubkey_inout->pubkey, &in_out_len, true);
    pubkey_inout->compressed = true;
}


btc_bool btc_key_sign_hash(const btc_key* privkey, const uint8_t* hash, unsigned char* sigout, size_t* outlen)
{
    return btc_ecc_sign(privkey->privkey, hash, sigout, outlen);
}


btc_bool btc_key_sign_hash_compact(const btc_key* privkey, const uint8_t* hash, unsigned char* sigout, size_t* outlen)
{
    return btc_ecc_sign_compact(privkey->privkey, hash, sigout, outlen);
}


btc_bool btc_pubkey_verify_sig(const btc_pubkey* pubkey, const uint8_t* hash, unsigned char* sigder, int len)
{
    return btc_ecc_verify_sig(pubkey->pubkey, pubkey->compressed, hash, sigder, len);
}
