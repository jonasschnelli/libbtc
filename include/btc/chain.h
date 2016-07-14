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

#ifndef __LIBBTC_CHAIN_H__
#define __LIBBTC_CHAIN_H__

#include "btc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>

typedef struct btc_chain {
    char chainname[32];
    uint8_t b58prefix_pubkey_address;
    uint8_t b58prefix_script_address;
    uint8_t b58prefix_secret_address; //!private key
    uint32_t b58prefix_bip32_privkey;
    uint32_t b58prefix_bip32_pubkey;
    const unsigned char netmagic[4];
    uint8_t genesisblockhash[32];
} btc_chain;

static const btc_chain btc_chain_main = {
    "main",
    0x00,
    0x05,
    0x80,
    0x0488ADE4,
    0x0488B21E,
    {0xf9, 0xbe, 0xb4, 0xd9},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68, 0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93, 0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1, 0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f}
};
static const btc_chain btc_chain_test = {
    "testnet3",
    0x6f,
    0xc4,
    0xEF,
    0x04358394,
    0x043587CF,
    {0x0b, 0x11, 0x09, 0x07},
    {0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97, 0x79, 0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8, 0xd7, 0x7f, 0x49, 0x43}
};
static const btc_chain btc_chain_regt = {
    "regtest",
    0x6f,
    0xc4,
    0xEF,
    0x04358394,
    0x043587CF,
    {0xfa, 0xbf, 0xb5, 0xda},
    {0x0f, 0x91, 0x88, 0xf1, 0x3c, 0xb7, 0xb2, 0xc7, 0x1f, 0x2a, 0x33, 0x5e, 0x3a, 0x4f, 0xc3, 0x28, 0xbf, 0x5b, 0xeb, 0x43, 0x60, 0x12, 0xaf, 0xca, 0x59, 0x0b, 0x1a, 0x11, 0x46, 0x6e, 0x22, 0x06}
};

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_CHAIN_H__
