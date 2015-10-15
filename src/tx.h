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


#ifndef LIBBTC_TX_H_
#define LIBBTC_TX_H_


#include <stdint.h>
#include <stddef.h>
#include <stdint.h>

#include "cstr.h"
#include "vector.h"

typedef uint8_t uint256[32];


typedef struct lbc_script_
{
    int* data;
    size_t limit; // Total size of the vector
    size_t current; //Number of vectors in it at present
} lbc_script;

typedef struct lbc_tx_outpoint_
{
    uint256 hash;
    uint32_t n;
} lbc_tx_outpoint;

typedef struct lbc_tx_in_
{
    lbc_tx_outpoint prevout;
    cstring *script_sig;
    uint32_t sequence;
} lbc_tx_in;

typedef struct lbc_tx_out_
{
    int64_t value;
    cstring *script_pubkey;
} lbc_tx_out;

typedef struct lbc_tx_
{
    uint32_t version;
    vector *vin;
    vector *vout;
    uint32_t locktime;
} lbc_tx;


//!create a new tx input
lbc_tx_in* lbc_tx_in_new();
void lbc_tx_in_free(lbc_tx_in *tx_in);
void lbc_tx_in_copy(lbc_tx_in *dest, const lbc_tx_in *src);

//!create a new tx output
lbc_tx_out* lbc_tx_out_new();
void lbc_tx_out_free(lbc_tx_out *tx_out);
void lbc_tx_out_copy(lbc_tx_out *dest, const lbc_tx_out *src);

//!create a new tx input
lbc_tx* lbc_tx_new();
void lbc_tx_free(lbc_tx *tx);
void lbc_tx_copy(lbc_tx *dest, const lbc_tx *src);

//!deserialize/parse a p2p serialized bitcoin transaction
int lbc_tx_deserialize(const unsigned char *tx_serialized, size_t inlen, lbc_tx *tx);

//!serialize a lbc bitcoin data structure into a p2p serialized buffer
void lbc_tx_serialize(cstring *s, const lbc_tx *tx);

bool lbc_tx_sighash(const lbc_tx *tx_to, const cstring *fromPubKey, unsigned int in_num, int hashtype, uint8_t *hash);

#endif //LIBBTC_TX_H_
