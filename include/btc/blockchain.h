/*

 The MIT License (MIT)

 Copyright (c) 2016 Libbtc Developers

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

#ifndef __LIBBTC_BLOCKCHAIN_H__
#define __LIBBTC_BLOCKCHAIN_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "block.h"
#include "btc.h"

#include <stdint.h>
#include <sys/types.h>

typedef struct btc_blockindex {
    uint32_t height;
    uint256 hash;
    btc_block_header header;
    struct btc_blockindex* prev;
} btc_blockindex;

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_BLOCKCHAIN_H__
