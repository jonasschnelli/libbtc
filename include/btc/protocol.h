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

#ifndef __LIBBTC_PROTOCOL_H__
#define __LIBBTC_PROTOCOL_H__

#include "btc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <btc/buffer.h>
#include <btc/cstr.h>
#include <btc/vector.h>

#include <arpa/inet.h>

#define BTC_P2P_HDRSZ	(4 + 12 + 4 + 4) /* magic, command, length, checksum */

static const unsigned int MAX_HEADERS_RESULTS = 2000;

typedef struct btc_p2p_msg_hdr_ {
    unsigned char	netmagic[4];
    char            command[12];
    uint32_t        data_len;
    unsigned char	hash[4];
} btc_p2p_msg_hdr;

typedef struct btc_p2p_address_ {
    uint32_t        time;
    uint64_t        services;
    unsigned char	ip[16];
    uint16_t        port;
} btc_p2p_address;

typedef struct btc_p2p_blockheader_ {
    int32_t         version;
    uint8_t         prev_block[32];
    uint8_t         merkle_root[32];
    uint32_t        timestamp;
    uint32_t        diff_bits;
    uint32_t        nonce;
    uint32_t        tx_count;
} btc_p2p_blockheader;

/* btc_p2p_message_new does malloc a cstring, needs cleanup afterwards! */
LIBBTC_API cstring *btc_p2p_message_new(const unsigned char netmagic[4], const char *command, const void *data, uint32_t data_len);

/* creates version message and writes it to str_out*/
LIBBTC_API void btc_p2p_msg_version(const btc_p2p_address *addrFrom, const btc_p2p_address *addrTo, const char *strSubVer, cstring *str_out);

/* creates a getheader message */
LIBBTC_API void btc_p2p_msg_getheaders(vector *blocklocators, uint8_t *hashstop, cstring *str_out);

/* copies over a sockaddr (IPv4/IPv6) to a p2p address struct */ 
LIBBTC_API void btc_addr_to_p2paddr(struct sockaddr *addr, btc_p2p_address *addr_out);
LIBBTC_API void btc_p2p_ser_addr(cstring *s, unsigned int protover, const btc_p2p_address *addr);
LIBBTC_API btc_bool btc_p2p_set_addr(btc_p2p_address *addr_out);
LIBBTC_API void btc_p2p_deser_msghdr(btc_p2p_msg_hdr *hdr, struct const_buffer* buf);

LIBBTC_API void btc_p2p_deser_blockheader(btc_p2p_blockheader *blockheader, struct const_buffer* buf);
LIBBTC_API void btc_p2p_ser_blockheader(btc_p2p_blockheader *blockheader, cstring* buf);
LIBBTC_API void btc_p2p_blockheader_hash(btc_p2p_blockheader *blockheader, uint8_t *hash_out);
#ifdef __cplusplus
}
#endif

#endif // __LIBBTC_PROTOCOL_H__
