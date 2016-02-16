/*

 The MIT License (MIT)

 Copyright (c) 2012 exMULTI, Inc.
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

#ifndef LIBBTC_VECTOR_H__
#define LIBBTC_VECTOR_H__

#include <stdint.h>

#include "buffer.h"
#include "btc/cstr.h"
#include "btc/vector.h"

#include "portable_endian.h"

extern void ser_bytes(cstring* s, const void* p, size_t len);
extern void ser_u16(cstring* s, uint16_t v_);
extern void ser_u32(cstring* s, uint32_t v_);
extern void ser_i32(cstring* s, int32_t v_);
extern void ser_u64(cstring* s, uint64_t v_);
static inline void ser_u256(cstring* s, const unsigned char* v_)
{
    ser_bytes(s, v_, 32);
}

extern void ser_varlen(cstring* s, uint32_t vlen);
extern void ser_str(cstring* s, const char* s_in, size_t maxlen);
extern void ser_varstr(cstring* s, cstring* s_in);

static inline void ser_s32(cstring* s, int32_t v_)
{
    ser_u32(s, (uint32_t)v_);
}

static inline void ser_s64(cstring* s, int64_t v_)
{
    ser_u64(s, (uint64_t)v_);
}

extern void ser_u256_vector(cstring* s, vector* vec);

extern btc_bool deser_skip(struct const_buffer* buf, size_t len);
extern btc_bool deser_bytes(void* po, struct const_buffer* buf, size_t len);
extern btc_bool deser_u16(uint16_t* vo, struct const_buffer* buf);
extern btc_bool deser_u32(uint32_t* vo, struct const_buffer* buf);
extern btc_bool deser_u64(uint64_t* vo, struct const_buffer* buf);

extern btc_bool deser_i32(int32_t* vo, struct const_buffer* buf);


static inline btc_bool deser_u256(uint8_t* vo, struct const_buffer* buf)
{
    return deser_bytes(vo, buf, 32);
}

extern btc_bool deser_varlen(uint32_t* lo, struct const_buffer* buf);
extern btc_bool deser_str(char* so, struct const_buffer* buf, size_t maxlen);
extern btc_bool deser_varstr(cstring** so, struct const_buffer* buf);

static inline btc_bool deser_s64(int64_t* vo, struct const_buffer* buf)
{
    return deser_u64((uint64_t*)vo, buf);
}

extern btc_bool deser_u256_vector(vector** vo, struct const_buffer* buf);

//extern void u256_from_compact(BIGNUM *vo, uint32_t c);

#endif /* LIBBTC_VECTOR_H__ */
