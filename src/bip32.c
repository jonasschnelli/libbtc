/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c) 2015 Douglas J. Bakkumk
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


#include "btc/bip32.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include "btc/base58.h"
#include "btc/ecc.h"

#include "ripemd160.h"
#include "sha2.h"
#include "utils.h"

// write 4 big endian bytes
static void write_be(uint8_t *data, uint32_t x)
{
    data[0] = x >> 24;
    data[1] = x >> 16;
    data[2] = x >> 8;
    data[3] = x;
}


// read 4 big endian bytes
static uint32_t read_be(const uint8_t *data)
{
    return (((uint32_t)data[0]) << 24) |
           (((uint32_t)data[1]) << 16) |
           (((uint32_t)data[2]) << 8)  |
           (((uint32_t)data[3]));
}


bool hdnode_from_seed(const uint8_t *seed, int seed_len, HDNode *out)
{
    uint8_t I[32 + 32];
    memset(out, 0, sizeof(HDNode));
    out->depth = 0;
    out->fingerprint = 0x00000000;
    out->child_num = 0;
    hmac_sha512((const uint8_t *)"Bitcoin seed", 12, seed, seed_len, I);
    memcpy(out->private_key, I, 32);

    if (!ecc_verify_privatekey(out->private_key)) {
        memset(I, 0, sizeof(I));
        return false;
    }

    memcpy(out->chain_code, I + 32, 32);
    hdnode_fill_public_key(out);
    memset(I, 0, sizeof(I));
    return true;
}


bool hdnode_public_ckd(HDNode *inout, uint32_t i)
{
    uint8_t data[1 + 32 + 4];
    uint8_t I[32 + 32];
    uint8_t fingerprint[32];

    if (i & 0x80000000) { // private derivation
        return false;
    } else { // public derivation
        memcpy(data, inout->public_key, 33);
    }
    write_be(data + 33, i);

    sha256_Raw(inout->public_key, 33, fingerprint);
    ripemd160(fingerprint, 32, fingerprint);
    inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) + (fingerprint[2] << 8) + fingerprint[3];

    memset(inout->private_key, 0, 32);

    int failed = 0;
    hmac_sha512(inout->chain_code, 32, data, sizeof(data), I);
    memcpy(inout->chain_code, I + 32, 32);


    if (!ecc_public_key_tweak_add(inout->public_key, I))
        failed = false;

    if (!failed) {
        inout->depth++;
        inout->child_num = i;
    }

    // Wipe all stack data.
    memset(data, 0, sizeof(data));
    memset(I, 0, sizeof(I));
    memset(fingerprint, 0, sizeof(fingerprint));
    
    return failed ? false : true;
}


bool hdnode_private_ckd(HDNode *inout, uint32_t i)
{
    uint8_t data[1 + 32 + 4];
    uint8_t I[32 + 32];
    uint8_t fingerprint[32];
    uint8_t p[32], z[32];

    if (i & 0x80000000) { // private derivation
        data[0] = 0;
        memcpy(data + 1, inout->private_key, 32);
    } else { // public derivation
        memcpy(data, inout->public_key, 33);
    }
    write_be(data + 33, i);

    sha256_Raw(inout->public_key, 33, fingerprint);
    ripemd160(fingerprint, 32, fingerprint);
    inout->fingerprint = (fingerprint[0] << 24) + (fingerprint[1] << 16) +
                         (fingerprint[2] << 8) + fingerprint[3];

    memset(fingerprint, 0, sizeof(fingerprint));
    memcpy(p, inout->private_key, 32);

    hmac_sha512(inout->chain_code, 32, data, sizeof(data), I);
    memcpy(inout->chain_code, I + 32, 32);
    memcpy(inout->private_key, I, 32);

    memcpy(z, inout->private_key, 32);

    int failed = 0;
    if (!ecc_verify_privatekey(z)) {
        failed = 1;
        return false;
    }

    memcpy(inout->private_key, p, 32);
    if (!ecc_private_key_tweak_add(inout->private_key, z)) {
        failed = 1;
    }

    if (!failed)
    {
        inout->depth++;
        inout->child_num = i;
        hdnode_fill_public_key(inout);
    }

    memset(data, 0, sizeof(data));
    memset(I, 0, sizeof(I));
    memset(p, 0, sizeof(p));
    memset(z, 0, sizeof(z));
    return true;
}


void hdnode_fill_public_key(HDNode *node)
{
    ecc_get_public_key33(node->private_key, node->public_key);
}


static void hdnode_serialize(const HDNode *node, uint32_t version, char use_public,
                             char *str, int strsize)
{
    uint8_t node_data[78];
    write_be(node_data, version);
    node_data[4] = node->depth;
    write_be(node_data + 5, node->fingerprint);
    write_be(node_data + 9, node->child_num);
    memcpy(node_data + 13, node->chain_code, 32);
    if (use_public) {
        memcpy(node_data + 45, node->public_key, 33);
    } else {
        node_data[45] = 0;
        memcpy(node_data + 46, node->private_key, 32);
    }
    base58_encode_check(node_data, 78, str, strsize);
}


void hdnode_serialize_public(const HDNode *node, char *str, int strsize)
{
    hdnode_serialize(node, 0x0488B21E, 1, str, strsize);
}


void hdnode_serialize_private(const HDNode *node, char *str, int strsize)
{
    hdnode_serialize(node, 0x0488ADE4, 0, str, strsize);
}


// check for validity of curve point in case of public data not performed
bool hdnode_deserialize(const char *str, HDNode *node)
{
    uint8_t node_data[78];
    memset(node, 0, sizeof(HDNode));
    if (!base58_decode_check(str, node_data, sizeof(node_data))) {
        return false;
    }
    uint32_t version = read_be(node_data);
    if (version == 0x0488B21E) { // public node
        memcpy(node->public_key, node_data + 45, 33);
    } else if (version == 0x0488ADE4) { // private node
        if (node_data[45]) { // invalid data
            return false;
        }
        memcpy(node->private_key, node_data + 46, 32);
        hdnode_fill_public_key(node);
    } else {
        return false; // invalid version
    }
    node->depth = node_data[4];
    node->fingerprint = read_be(node_data + 5);
    node->child_num = read_be(node_data + 9);
    memcpy(node->chain_code, node_data + 13, 32);
    return true;
}

bool hd_generate_key(HDNode *node, const char *keypath, const uint8_t *privkeymaster,
                        const uint8_t *chaincode)
{
    static char delim[] = "/";
    static char prime[] = "phH\'";
    static char digits[] = "0123456789";
    uint64_t idx = 0;
    assert(strlens(keypath) < 1024);
    char *pch, *kp = malloc(strlens(keypath) + 1);

    if (!kp) {
        return false;
    }

    if (strlens(keypath) < strlens("m/")) {
        goto err;
    }

    memset(kp, 0, strlens(keypath) + 1);
    memcpy(kp, keypath, strlens(keypath));

    if (kp[0] != 'm' || kp[1] != '/') {
        goto err;
    }

    node->depth = 0;
    node->child_num = 0;
    node->fingerprint = 0;
    memcpy(node->chain_code, chaincode, 32);
    memcpy(node->private_key, privkeymaster, 32);
    hdnode_fill_public_key(node);

    pch = strtok(kp + 2, delim);
    while (pch != NULL) {
        size_t i = 0;
        int prm = 0;
        for ( ; i < strlens(pch); i++) {
            if (strchr(prime, pch[i])) {
                if (i != strlens(pch) - 1) {
                    goto err;
                }
                prm = 1;
            } else if (!strchr(digits, pch[i])) {
                goto err;
            }
        }

        idx = strtoull(pch, NULL, 10);
        if (idx > UINT32_MAX) {
            goto err;
        }

        if (prm) {
            if (hdnode_private_ckd_prime(node, idx) != true) {
                goto err;
            }
        } else {
            if (hdnode_private_ckd(node, idx) != true) {
                goto err;
            }
        }
        pch = strtok(NULL, delim);
    }
    free(kp);
    return true;

err:
    free(kp);
    return false;
}
