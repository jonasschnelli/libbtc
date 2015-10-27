/*

 The MIT License (MIT)

 Copyright 2012 exMULTI, Inc.
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

#include <btc/script.h>

#include <assert.h>
#include <string.h>

#include "buffer.h"
#include "serialize.h"

btc_bool btc_script_copy_without_op_codeseperator(const cstring* script_in, cstring* script_out)
{
    if (script_in->len == 0)
        return false; /* EOF */

    struct const_buffer buf = {script_in->str, script_in->len};
    unsigned char opcode;
    while (buf.len > 0) {
        if (!deser_bytes(&opcode, &buf, 1))
            goto err_out;

        uint32_t data_len;

        if (opcode == OP_CODESEPARATOR)
            continue;

        else if (opcode == OP_PUSHDATA1) {
            uint8_t v8;
            if (!deser_bytes(&v8, &buf, 1))
                goto err_out;
            data_len = v8;
        } else if (opcode == OP_PUSHDATA2) {
            uint16_t v16;
            if (!deser_u16(&v16, &buf))
                goto err_out;
            data_len = v16;
        } else if (opcode == OP_PUSHDATA4) {
            uint32_t v32;
            if (!deser_u32(&v32, &buf))
                goto err_out;
            data_len = v32;
        } else {
            cstr_append_buf(script_out, &opcode, 1);
            continue;
        }

        cstr_append_buf(script_out, buf.p, data_len);
        if (!deser_skip(&buf, data_len))
            goto err_out;
    }

err_out:
    return false;
}

btc_script_op* btc_script_op_new()
{
    btc_script_op* script_op;
    script_op = calloc(1, sizeof(*script_op));

    return script_op;
}


void btc_script_op_free(btc_script_op* script_op)
{
    if (script_op->data) {
        free(script_op->data);
        script_op->data = NULL;
    }
    script_op->datalen = 0;
    script_op->op = OP_0;
}

void btc_script_op_free_cb(void* data)
{
    btc_script_op* script_op = data;
    btc_script_op_free(script_op);

    free(script_op);
}

btc_bool btc_script_get_ops(const cstring* script_in, vector* ops_out)
{
    if (script_in->len == 0)
        return false; /* EOF */

    struct const_buffer buf = {script_in->str, script_in->len};
    unsigned char opcode;

    btc_script_op* op = NULL;
    while (buf.len > 0) {
        op = btc_script_op_new();

        if (!deser_bytes(&opcode, &buf, 1))
            goto err_out;

        op->op = opcode;

        uint32_t data_len;

        if (opcode < OP_PUSHDATA1) {
            data_len = opcode;
        } else if (opcode == OP_PUSHDATA1) {
            uint8_t v8;
            if (!deser_bytes(&v8, &buf, 1))
                goto err_out;
            data_len = v8;
        } else if (opcode == OP_PUSHDATA2) {
            uint16_t v16;
            if (!deser_u16(&v16, &buf))
                goto err_out;
            data_len = v16;
        } else if (opcode == OP_PUSHDATA4) {
            uint32_t v32;
            if (!deser_u32(&v32, &buf))
                goto err_out;
            data_len = v32;
        } else {
            vector_add(ops_out, op);
            continue;
        }

        op->data = calloc(1, data_len);
        memcpy(op->data, &buf.p, data_len);
        op->datalen = data_len;

        vector_add(ops_out, op);

        if (!deser_skip(&buf, data_len))
            goto err_out;
    }

    return true;
err_out:
    btc_script_op_free(op);
    return false;
}

static inline btc_bool btc_script_is_pushdata(enum opcodetype op)
{
    return (op <= OP_PUSHDATA4);
}

static btc_bool btc_script_is_op(const btc_script_op* op, enum opcodetype opcode)
{
    return (op->op == opcode);
}

static btc_bool btc_script_is_op_pubkey(const btc_script_op* op)
{
    if (!btc_script_is_pushdata(op->op))
        return false;
    if (op->datalen < 33 || op->datalen > 120)
        return false;
    return true;
}

static btc_bool btc_script_is_op_pubkeyhash(const btc_script_op* op)
{
    if (!btc_script_is_pushdata(op->op))
        return false;
    if (op->datalen != 20)
        return false;
    return true;
}

// OP_PUBKEY, OP_CHECKSIG
btc_bool btc_script_is_pubkey(vector* ops)
{
    return ((ops->len == 2) &&
            btc_script_is_op(vector_idx(ops, 1), OP_CHECKSIG) &&
            btc_script_is_op_pubkey(vector_idx(ops, 0)));
}

// OP_DUP, OP_HASH160, OP_PUBKEYHASH, OP_EQUALVERIFY, OP_CHECKSIG,
btc_bool btc_script_is_pubkeyhash(vector* ops)
{
    return ((ops->len == 5) &&
            btc_script_is_op(vector_idx(ops, 0), OP_DUP) &&
            btc_script_is_op(vector_idx(ops, 1), OP_HASH160) &&
            btc_script_is_op_pubkeyhash(vector_idx(ops, 2)) &&
            btc_script_is_op(vector_idx(ops, 3), OP_EQUALVERIFY) &&
            btc_script_is_op(vector_idx(ops, 4), OP_CHECKSIG));
}

// OP_HASH160, OP_PUBKEYHASH, OP_EQUAL
btc_bool btc_script_is_scripthash(vector* ops)
{
    return ((ops->len == 3) &&
            btc_script_is_op(vector_idx(ops, 0), OP_HASH160) &&
            btc_script_is_op_pubkeyhash(vector_idx(ops, 1)) &&
            btc_script_is_op(vector_idx(ops, 2), OP_EQUAL));
}

static btc_bool btc_script_is_op_smallint(const btc_script_op* op)
{
    return ((op->op == OP_0) ||
            (op->op >= OP_1 && op->op <= OP_16));
}

btc_bool btc_script_is_multisig(vector* ops)
{
    if ((ops->len < 3) || (ops->len > (16 + 3)) ||
        !btc_script_is_op_smallint(vector_idx(ops, 0)) ||
        !btc_script_is_op_smallint(vector_idx(ops, ops->len - 2)) ||
        !btc_script_is_op(vector_idx(ops, ops->len - 1), OP_CHECKMULTISIG))
        return false;

    unsigned int i;
    for (i = 1; i < (ops->len - 2); i++)
        if (!btc_script_is_op_pubkey(vector_idx(ops, i)))
            return false;

    return true;
}

enum btc_tx_out_type btc_script_classify(vector* ops)
{
    if (btc_script_is_pubkeyhash(ops))
        return BTC_TX_PUBKEYHASH;
    if (btc_script_is_scripthash(ops))
        return BTC_TX_SCRIPTHASH;
    if (btc_script_is_pubkey(ops))
        return BTC_TX_PUBKEY;
    if (btc_script_is_multisig(ops))
        return BTC_TX_MULTISIG;

    return BTC_TX_NONSTANDARD;
}

static enum opcodetype btc_encode_op_n(int n)
{
    assert(n >= 0 && n <= 16);
    if (n == 0)
        return OP_0;
    return (enum opcodetype)(OP_1+n-1);
}


static void btc_script_append_op(cstring* script_in, enum opcodetype op)
{
    cstr_append_buf(script_in, &op, 1);
}


static void btc_script_append_pushdata(cstring* script_in, unsigned char *data, size_t datalen)
{
    if (datalen < OP_PUSHDATA1)
    {
        cstr_append_buf(script_in, (unsigned char *)&datalen, 1);
    }
    else if (datalen <= 0xff)
    {
        btc_script_append_op(script_in, OP_PUSHDATA1);
        cstr_append_buf(script_in, (unsigned char *)&datalen, 1);
    }
    else if (datalen <= 0xffff)
    {
        btc_script_append_op(script_in, OP_PUSHDATA2);
        uint16_t v = htole16(datalen);
        cstr_append_buf(script_in, &v, sizeof(v));
    }
    else
    {
        btc_script_append_op(script_in, OP_PUSHDATA4);
        uint32_t v = htole32(datalen);
        cstr_append_buf(script_in, &v, sizeof(v));
    }
    cstr_append_buf(script_in, data, datalen);
}

btc_bool btc_script_build_multisig(cstring* script_in, unsigned int required_signatures, vector *pubkeys_chars)
{
    cstr_resize(script_in, 0); //clear script

    if(required_signatures > 16 || pubkeys_chars->len > 16)
        return false;
    enum opcodetype op_req_sig = btc_encode_op_n(required_signatures);
    cstr_append_buf(script_in, &op_req_sig, 1);

    int i;
    for (i = 0; i < (int)pubkeys_chars->len; i++)
    {
        btc_pubkey *pkey = pubkeys_chars->data[i];
        btc_script_append_pushdata(script_in, pkey->pubkey, (pkey->compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH));
    }

    enum opcodetype op_pub_len = btc_encode_op_n(pubkeys_chars->len);
    cstr_append_buf(script_in, &op_pub_len, 1);

    enum opcodetype op_checkmultisig = OP_CHECKMULTISIG;
    cstr_append_buf(script_in, &op_checkmultisig, 1);

    return true;
}

btc_bool btc_script_build_p2pkh(cstring* script_in, const uint8_t *hash160)
{
    cstr_resize(script_in, 0); //clear script

    btc_script_append_op(script_in, OP_DUP);
    btc_script_append_op(script_in, OP_HASH160);


    btc_script_append_pushdata(script_in, hash160, 20);
    btc_script_append_op(script_in, OP_EQUALVERIFY);
    btc_script_append_op(script_in, OP_CHECKSIG);

    return true;
}

btc_bool btc_script_build_p2sh(cstring* script_in, const uint8_t *hash160)
{
    cstr_resize(script_in, 0); //clear script
    btc_script_append_op(script_in, OP_HASH160);
    btc_script_append_pushdata(script_in, hash160, 20);
    btc_script_append_op(script_in, OP_EQUAL);

    return true;
}
