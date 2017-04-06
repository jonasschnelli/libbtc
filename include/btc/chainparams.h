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

#ifndef __LIBBTC_CHAINPARAMS_H__
#define __LIBBTC_CHAINPARAMS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "btc.h"

#include <stdint.h>
#include <sys/types.h>

typedef struct btc_dns_seed_ {
    char domain[256];
} btc_dns_seed;

typedef struct btc_chainparams_ {
    char chainname[32];
    uint8_t b58prefix_pubkey_address;
    uint8_t b58prefix_script_address;
    uint8_t b58prefix_secret_address; //!private key
    uint32_t b58prefix_bip32_privkey;
    uint32_t b58prefix_bip32_pubkey;
    const unsigned char netmagic[4];
    uint8_t genesisblockhash[32];
    int default_port;
    btc_dns_seed dnsseeds[8];
} btc_chainparams;

static const btc_chainparams btc_chainparams_main = {
    "main",
    0x00,
    0x05,
    0x80,
    0x0488ADE4,
    0x0488B21E,
    {0xf9, 0xbe, 0xb4, 0xd9},
    {0x6f,0xe2,0x8c,0x0a,0xb6,0xf1,0xb3,0x72,0xc1,0xa6,0xa2,0x46,0xae,0x63,0xf7,0x4f,0x93,0x1e,0x83,0x65,0xe1,0x5a,0x08,0x9c,0x68,0xd6,0x19,0x00,0x00,0x00,0x00,0x00},
    8333,
    { {"seed.bitcoin.jonasschnelli.ch"}, 0 }
};
static const btc_chainparams btc_chainparams_test = {
    "testnet3",
    0x6f,
    0xc4,
    0xEF,
    0x04358394,
    0x043587CF,
    {0x0b, 0x11, 0x09, 0x07},
    {0x43,0x49,0x7f,0xd7,0xf8,0x26,0x95,0x71,0x08,0xf4,0xa3,0x0f,0xd9,0xce,0xc3,0xae,0xba,0x79,0x97,0x20,0x84,0xe9,0x0e,0xad,0x01,0xea,0x33,0x09,0x00,0x00,0x00,0x00},
    18333,
    { {"testnet-seed.bitcoin.jonasschnelli.ch"}, 0 }
};
static const btc_chainparams btc_chainparams_regtest = {
    "regtest",
    0x6f,
    0xc4,
    0xEF,
    0x04358394,
    0x043587CF,
    {0xfa, 0xbf, 0xb5, 0xda},
    {0x06,0x22,0x6e,0x46,0x11,0x1a,0x0b,0x59,0xca,0xaf,0x12,0x60,0x43,0xeb,0x5b,0xbf,0x28,0xc3,0x4f,0x3a,0x5e,0x33,0x2a,0x1f,0xc7,0xb2,0xb7,0x3c,0xf1,0x88,0x91,0x0f},
    18444,
    { 0 }
};

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_CHAINPARAMS_H__
