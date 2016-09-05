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

static unsigned int NULLHASH[32] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

enum service_bits {
    BTC_NODE_NETWORK	= (1 << 0),
};

static const char *BTC_MSG_VERSION      = "version";
static const char *BTC_MSG_VERACK       = "verack";
static const char *BTC_MSG_PING         = "ping";
static const char *BTC_MSG_PONG         = "pong";
static const char *BTC_MSG_GETHEADERS   = "getheaders";
static const char *BTC_MSG_HEADERS      = "headers";

static const unsigned int MAX_HEADERS_RESULTS = 2000;
static const int BTC_PROTOCOL_VERSION = 70014;

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

typedef struct btc_p2p_version_msg_ {
    int32_t         version;
    uint64_t        services;
    int64_t         timestamp;
    btc_p2p_address addr_recv;
    btc_p2p_address addr_from;
    uint64_t        nonce;
    char	        useragent[128];
    int32_t         start_height;
    uint8_t         relay;
} btc_p2p_version_msg;

/* =================================== */
/* VERSION MESSAGE */
/* =================================== */

/* creates version message and writes it to str_out*/
LIBBTC_API void btc_p2p_msg_version_init(btc_p2p_version_msg *msg, const btc_p2p_address *addrFrom, const btc_p2p_address *addrTo, const char *strSubVer);

/* serialize a p2p "version" message */
LIBBTC_API void btc_p2p_msg_version_ser(btc_p2p_version_msg *msg, cstring* buf);

/* deserialize a p2p "version" message */
LIBBTC_API btc_bool btc_p2p_msg_version_deser(btc_p2p_version_msg *msg, struct const_buffer* buf);



/* =================================== */
/* ADDR MESSAGE */
/* =================================== */

/* initializes a p2p address structure */
LIBBTC_API void btc_p2p_address_init(btc_p2p_address *addr);

/* copy over a sockaddr (IPv4/IPv6) to a p2p address struct */
LIBBTC_API void btc_addr_to_p2paddr(struct sockaddr *addr, btc_p2p_address *addr_out);

/* deserialize a p2p address */
LIBBTC_API btc_bool btc_p2p_deser_addr(unsigned int protocol_version, btc_p2p_address *addr, struct const_buffer *buf);

/* serialize a p2p addr */
LIBBTC_API void btc_p2p_ser_addr(unsigned int protover, const btc_p2p_address *addr, cstring *str_out);

/* copy over a p2p addr to a sockaddr object */
LIBBTC_API void btc_p2paddr_to_addr(btc_p2p_address *p2p_addr, struct sockaddr *addr_out);


/* =================================== */
/* P2P MSG-HDR */
/* =================================== */

/* deserialize the p2p message header from a buffer */
LIBBTC_API void btc_p2p_deser_msghdr(btc_p2p_msg_hdr *hdr, struct const_buffer* buf);

/* btc_p2p_message_new does malloc a cstring, needs cleanup afterwards! */
LIBBTC_API cstring *btc_p2p_message_new(const unsigned char netmagic[4], const char *command, const void *data, uint32_t data_len);


/* =================================== */
/* GETHEADER MESSAGE */
/* =================================== */

/* creates a getheader message */
LIBBTC_API void btc_p2p_msg_getheaders(vector *blocklocators, uint8_t *hashstop, cstring *str_out);

/* directly deserialize a getheaders message to blocklocators, hashstop */
LIBBTC_API btc_bool btc_p2p_deser_msg_getheaders(vector *blocklocators, uint8_t *hashstop, struct const_buffer *buf);


#ifdef __cplusplus
}
#endif

#endif // __LIBBTC_PROTOCOL_H__
