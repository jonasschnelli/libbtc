/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utils.h"

void test_utils()
{
    char hash[] = "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1";
    uint8_t *hash_bin = utils_hex_to_uint8(hash);
    char *new = utils_uint8_to_hex(hash_bin, 32);
    assert(strncmp(new, hash, 64) == 0);

    uint64_t bigint = 0xFFFFFFFFFFFFFFFF;
    char vint[255];
    int outlen;
    utils_uint64_to_varint(vint, &outlen, bigint);
    assert(outlen = 16);
    assert(strncmp("ffffffffffffffffff", vint, outlen) == 0);

    memset(vint, 0, 255);
    bigint = 0xFA;
    utils_uint64_to_varint(vint, &outlen, bigint);
    assert(outlen = 2);
    assert(strncmp("fa", vint, outlen) == 0);

    memset(vint, 0, 255);
    bigint = 0xFFA;
    utils_uint64_to_varint(vint, &outlen, bigint);
    assert(outlen = 4);
    assert(strncmp("fdfa0f", vint, outlen) == 0);

    memset(vint, 0, 255);
    bigint = 0xFFFFA;
    utils_uint64_to_varint(vint, &outlen, bigint);
    assert(outlen = 8);
    assert(strncmp("fefaff0f00", vint, outlen) == 0);

    char varint0[] = "fa";
    utils_varint_to_uint64(varint0, &bigint);
    assert(bigint == 250);

    char varint1[] = "ffffffffffffffffff";
    utils_varint_to_uint64(varint1, &bigint);
    assert(bigint == 0xFFFFFFFFFFFFFFFF);

    char varint2[] = "fdfa0f";
    utils_varint_to_uint64(varint2, &bigint);
    assert(bigint == 4090);

    char varint3[] = "fefaff0f00";
    utils_varint_to_uint64(varint3, &bigint);
    assert(bigint == 1048570);

    unsigned char data[] = {0x00, 0xFF, 0x00, 0xAA, 0x00, 0xFF, 0x00, 0xAA};
    char hex[sizeof(data)*2+1];
    utils_bin_to_hex(data, sizeof(data), hex);
    assert(strcmp(hex, "00ff00aa00ff00aa") == 0);

    unsigned char data2[sizeof(data)];
    utils_hex_to_bin(hex, data2, strlen(hex), &outlen);
    assert(outlen == 8);
    assert(memcmp(data, data2, outlen) == 0);
}
