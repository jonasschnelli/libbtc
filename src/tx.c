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

#include <stdint.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "flags.h"
#include "tx.h"
#include "serialize.h"

void lbc_tx_in_free(lbc_tx_in *tx_in)
{
    if (!tx_in)
        return;

    memset(&tx_in->prevout.hash, 0, 32);
    tx_in->prevout.n = 0;

    if (tx_in->script_sig) {
        cstr_free(tx_in->script_sig, true);
        tx_in->script_sig = NULL;
    }
}

//callback for vector free function
void lbc_tx_in_free_cb(void *data)
{
    if (!data)
        return;

   	lbc_tx_in *tx_in = data;
    lbc_tx_in_free(tx_in);

    memset(tx_in, 0, sizeof(*tx_in));
    free(tx_in);
}


lbc_tx_in* lbc_tx_in_new()
{
    lbc_tx_in *tx_in;
    tx_in = calloc(1, sizeof(*tx_in));
    memset(&tx_in->prevout, 0, sizeof(tx_in->prevout));

    return tx_in;
}


void lbc_tx_out_free(lbc_tx_out *tx_out)
{
    if (!tx_out)
        return;
    tx_out->value = 0;

    if (tx_out->script_pubkey) {
        cstr_free(tx_out->script_pubkey, true);
        tx_out->script_pubkey = NULL;
    }
}


void lbc_tx_out_free_cb(void *data)
{
    if (!data)
        return;

   	lbc_tx_out *tx_out = data;
    lbc_tx_out_free(tx_out);

    memset(tx_out, 0, sizeof(*tx_out));
    free(tx_out);
}


lbc_tx_out* lbc_tx_out_new()
{
    lbc_tx_out *tx_out;
    tx_out = calloc(1, sizeof(*tx_out));

    return tx_out;
}


void lbc_tx_free(lbc_tx *tx)
{
    if (tx->vin)
        vector_free(tx->vin, true);

    if (tx->vout)
        vector_free(tx->vout, true);

    free(tx);
}


lbc_tx* lbc_tx_new()
{
    lbc_tx* tx;
    tx = calloc(1, sizeof(*tx));
    tx->vin = vector_new(8, lbc_tx_in_free_cb);
    tx->vout = vector_new(8, lbc_tx_out_free_cb);
    tx->version = 0;
    tx->locktime = 0;
    return tx;
}


bool lbc_tx_in_deserialize(lbc_tx_in *tx_in, struct const_buffer *buf)
{
    deser_u256(tx_in->prevout.hash, buf);
    uint32_t outp;
    if (!deser_u32(&tx_in->prevout.n, buf)) return false;
    if (!deser_varstr(&tx_in->script_sig, buf)) return false;
    if (!deser_u32(&tx_in->sequence, buf)) return false;
    return true;
}

bool lbc_tx_out_deserialize(lbc_tx_out *tx_out, struct const_buffer *buf)
{
    if (!deser_s64(&tx_out->value, buf)) return false;
    if (!deser_varstr(&tx_out->script_pubkey, buf)) return false;
    return true;
}

int lbc_tx_deserialize(const unsigned char *tx_serialized, size_t inlen, lbc_tx *tx)
{
    struct const_buffer buf = { tx_serialized, inlen };

    //tx needs to be initialized
    deser_u32(&tx->version, &buf);
    uint32_t vlen;
    if (!deser_varlen(&vlen, &buf)) return false;

    unsigned int i;
    for (i = 0; i < vlen; i++) {
        lbc_tx_in *tx_in = lbc_tx_in_new();

        if (!lbc_tx_in_deserialize(tx_in, &buf)) {
            free(tx_in);
        }
        
        vector_add(tx->vin, tx_in);
    }

    if (!deser_varlen(&vlen, &buf)) return false;
    for (i = 0; i < vlen; i++) {
        lbc_tx_out *tx_out = lbc_tx_out_new();

        if (!lbc_tx_out_deserialize(tx_out, &buf)) {
            free(tx_out);
        }

        vector_add(tx->vout, tx_out);
    }
    return BTC_OK;
}

void lbc_tx_in_serialize(cstring *s, const lbc_tx_in *tx_in)
{
    ser_u256(s, tx_in->prevout.hash);
    ser_u32(s, tx_in->prevout.n);
    ser_varstr(s, tx_in->script_sig);
    ser_u32(s, tx_in->sequence);
}

void lbc_tx_out_serialize(cstring *s, const lbc_tx_out *tx_out)
{
    ser_s64(s, tx_out->value);
    ser_varstr(s, tx_out->script_pubkey);
}

void lbc_tx_serialize(cstring *s, const lbc_tx *tx)
{
    ser_u32(s, tx->version);

    ser_varlen(s, tx->vin ? tx->vin->len : 0);

    unsigned int i;
    if (tx->vin) {
        for (i = 0; i < tx->vin->len; i++) {
            lbc_tx_in *tx_in;

            tx_in = vector_idx(tx->vin, i);
            lbc_tx_in_serialize(s, tx_in);
        }
    }

    ser_varlen(s, tx->vout ? tx->vout->len : 0);

    if (tx->vout) {
        for (i = 0; i < tx->vout->len; i++) {
            lbc_tx_out *tx_out;
            
            tx_out = vector_idx(tx->vout, i);
            lbc_tx_out_serialize(s, tx_out);
        }
    }
    
    ser_u32(s, tx->locktime);
}


void lbc_tx_in_copy(lbc_tx_in *dest, const lbc_tx_in *src)
{
    
    memcpy(&dest->prevout, &src->prevout, sizeof(dest->prevout));
    dest->sequence = src->sequence;

    if (!src->script_sig)
        dest->script_sig = NULL;
    else {
        dest->script_sig = cstr_new_sz(src->script_sig->len);
        cstr_append_buf(dest->script_sig,
                        src->script_sig->str, src->script_sig->len);
    }
}


void lbc_tx_out_copy(lbc_tx_out *dest, const lbc_tx_out *src)
{
    dest->value = src->value;

    if (!src->script_pubkey)
        dest->script_pubkey = NULL;
    else {
        dest->script_pubkey = cstr_new_sz(src->script_pubkey->len);
        cstr_append_buf(dest->script_pubkey,
                        src->script_pubkey->str,
                        src->script_pubkey->len);
    }
}


void lbc_tx_copy(lbc_tx *dest, const lbc_tx *src)
{
    dest->version = src->version;
    dest->locktime = src->locktime;

    if (!src->vin)
        dest->vin = NULL;
    else {
        unsigned int i;

        if (dest->vin)
            vector_free(dest->vin, true);

        dest->vin = vector_new(src->vin->len, lbc_tx_in_free_cb);

        for (i = 0; i < src->vin->len; i++) {
            lbc_tx_in *tx_in_old, *tx_in_new;

            tx_in_old = vector_idx(src->vin, i);
            tx_in_new = malloc(sizeof(*tx_in_new));
            lbc_tx_in_copy(tx_in_new, tx_in_old);
            vector_add(dest->vin, tx_in_new);
        }
    }

    if (!src->vout)
        dest->vout = NULL;
    else {
        unsigned int i;

        if (dest->vout)
            vector_free(dest->vout, true);

        dest->vout = vector_new(src->vout->len,
                              lbc_tx_out_free_cb);

        for (i = 0; i < src->vout->len; i++) {
            lbc_tx_out *tx_out_old, *tx_out_new;
            
            tx_out_old = vector_idx(src->vout, i);
            tx_out_new = malloc(sizeof(*tx_out_new));
            lbc_tx_out_copy(tx_out_new, tx_out_old);
            vector_add(dest->vout, tx_out_new);
        }
    }
}

}