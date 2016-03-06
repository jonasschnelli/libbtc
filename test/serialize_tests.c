/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <btc/cstr.h>
#include "serialize.h"
#include "utils.h"

void test_serialize()
{
    char hex0[] = "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1";
    char hex1[] = "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c2";
    char hex2[] = "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c3";
    uint8_t* hash0 = malloc(32);
    uint8_t* hash1 = malloc(32);
    uint8_t* hash2 = malloc(32);

    memcpy(hash0, utils_hex_to_uint8(hex0), 32);
    memcpy(hash1, utils_hex_to_uint8(hex1), 32);
    memcpy(hash2, utils_hex_to_uint8(hex2), 32);
    vector* vec = vector_new(5, free);
    vector_add(vec, hash0);
    vector_add(vec, hash1);
    vector_add(vec, hash2);


    cstring* s = cstr_new_sz(200);
    ser_u256_vector(s, vec);
    vector_free(vec, true);

    vector* vec2 = vector_new(0, NULL);
    struct const_buffer buf = {s->str, s->len};
    deser_u256_vector(&vec2, &buf);

    vector_free(vec2, true);
    cstr_free(s, true);


    cstring* s2 = cstr_new_sz(200);
    ser_u16(s2, 0xAAFF);
    ser_u32(s2, 0xDDBBAAFF);
    ser_u64(s2, 0x99FF99FFDDBBAAFF);
    ser_varlen(s2, 10);
    ser_varlen(s2, 1000);
    ser_varlen(s2, 100000000);
    ser_str(s2, "test", 4);
    cstring* s3 = cstr_new("foo");
    ser_varstr(s2, s3);
    cstr_free(s3, true);
    // ser_varlen(s2, (uint64_t)0x9999999999999999); // uint64 varlen is not supported right now

    struct const_buffer buf2 = {s2->str, s2->len};
    uint16_t num0;
    deser_u16(&num0, &buf2);
    assert(num0 == 43775); //0xAAFF
    uint32_t num1;
    deser_u32(&num1, &buf2);
    assert(num1 == 3720063743); //0xDDBBAAFF
    uint64_t num2;
    deser_u64(&num2, &buf2);
    assert(num2 == 0x99FF99FFDDBBAAFF); //0x99FF99FFDDBBAAFF
    uint32_t num3;
    deser_varlen(&num3, &buf2);
    assert(num3 == 10);
    deser_varlen(&num3, &buf2);
    assert(num3 == 1000);
    deser_varlen(&num3, &buf2);
    assert(num3 == 100000000);


    char strbuf[255];
    deser_str(strbuf, &buf2, 255);
    assert(strncmp(strbuf, "test", 4) == 0);

    cstring* deser_test = cstr_new_sz(0);
    deser_varstr(&deser_test, &buf2);
    assert(strncmp(deser_test->str, "foo", 3) == 0);

    cstr_free(deser_test, true);

    cstr_free(s2, true);

    struct const_buffer buf3 = {NULL, 0};
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    int32_t i32;

    assert(deser_u16(&u16, &buf3) == false);
    assert(deser_u32(&u32, &buf3) == false);
    assert(deser_u64(&u64, &buf3) == false);
    assert(deser_i32(&i32, &buf3) == false);

}
