/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

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

#include "btc/protocol.h"
#include "btc/hash.h"
#include <btc/buffer.h>
#include <btc/serialize.h>
#include "btc/portable_endian.h"

#include <assert.h>
#include <time.h>

static const int PROTOCOL_VERSION = 70014;
static unsigned int nullhash[32] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
enum service_bits {
    NODE_NETWORK	= (1 << 0),
};

enum {
    BTC_ADDR_TIME_VERSION	= 31402,
    BTC_MIN_PROTO_VERSION	= 209,
};

cstring *btc_p2p_message_new(const unsigned char netmagic[4], const char *command, const void *data, uint32_t data_len)
{
    cstring *s = cstr_new_sz(BTC_P2P_HDRSZ + data_len);

    /* network identifier (magic number) */
    cstr_append_buf(s, netmagic, 4);

    /* command string */
    char command_null[12];
    memset(command_null, 0, 12);
    memcpy(command_null, command, strlen(command));
    //memset(command_null+strlen(command), 0, 12-strlen(command));
    cstr_append_buf(s, command_null, 12);

    /* data length, always 4 bytes */
    uint32_t data_len_le = htole32(data_len);
    cstr_append_buf(s, &data_len_le, 4);

    /* data checksum (first 4 bytes of the double sha256 hash of the pl) */
    unsigned char msghash[32];
    btc_hash(data, data_len, msghash);
    cstr_append_buf(s, &msghash[0], 4);

    /* data payload */
    if (data_len > 0)
        cstr_append_buf(s, data, data_len);

    return s;
}

btc_bool btc_p2p_deser_addr(unsigned int protover,
                   btc_p2p_address *addr, struct const_buffer *buf)
{
    if (protover >= BTC_ADDR_TIME_VERSION)
        if (!deser_u32(&addr->time, buf)) return false;
    if (!deser_u64(&addr->services, buf)) return false;
    if (!deser_bytes(&addr->ip, buf, 16)) return false;
    if (!deser_u16(&addr->port, buf)) return false;
    return true;
}

void btc_p2p_ser_addr(cstring *s, unsigned int protover, const btc_p2p_address *addr)
{
    if (protover >= BTC_ADDR_TIME_VERSION)
        ser_u32(s, addr->time);
    ser_u64(s, addr->services);
    ser_bytes(s, addr->ip, 16);
    ser_u16(s, addr->port);
}


void btc_addr_to_p2paddr(struct sockaddr *addr, btc_p2p_address *addr_out)
{
    if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)addr;
        memcpy(&addr_out->ip, &saddr->sin6_addr, 16);
        addr_out->port = ntohs(saddr->sin6_port);
    } else if (addr->sa_family == AF_INET) {
        struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
        memset(&addr_out->ip[0], 0, 10);
        memset(&addr_out->ip[10], 0xff, 2);
        memcpy(&addr_out->ip[12], &saddr->sin_addr, 4);
        addr_out->port = ntohs(saddr->sin_port);
    }
}

void btc_p2p_msg_version(const btc_p2p_address *addrFrom, const btc_p2p_address *addrTo, const char *strSubVer, cstring *s)
{
    assert(s);
    ser_u32(s, PROTOCOL_VERSION);
    ser_u64(s, 0);
    ser_s64(s, time(NULL));

    btc_p2p_ser_addr(s, BTC_MIN_PROTO_VERSION, addrTo);
    btc_p2p_ser_addr(s, BTC_MIN_PROTO_VERSION, addrFrom);

    ser_u64(s, ((uint64_t)arc4random() << 32) | (uint64_t)arc4random());
    ser_str(s, strSubVer, sizeof(strSubVer));
    ser_u32(s, 0);
    cstr_append_c(s, false);
}

void btc_p2p_msg_getheaders(vector *blocklocators, uint8_t *hashstop, cstring *s)
{
    unsigned int i;

    ser_u32(s, PROTOCOL_VERSION);
    ser_varlen(s, blocklocators->len);
    for (i=0; i<blocklocators->len;i++)
    {
        uint8_t *hash = vector_idx(blocklocators, i);
        ser_bytes(s, hash, 32);
    }
    if (hashstop)
        ser_bytes(s, hashstop, 32);
    else
        ser_bytes(s, nullhash, 32);
}

void btc_p2p_deser_msghdr(btc_p2p_msg_hdr *hdr, struct const_buffer* buf)
{
    deser_bytes(hdr->netmagic, buf, 4);
    deser_bytes(hdr->command, buf, 12);
    deser_u32(&hdr->data_len, buf);
    deser_bytes(hdr->hash, buf, 4);
}

void btc_p2p_deser_blockheader(btc_p2p_blockheader *blockheader, struct const_buffer* buf)
{
    deser_s32(&blockheader->version, buf);
    deser_u256((uint8_t *)&blockheader->prev_block, buf);
    deser_u256((uint8_t *)&blockheader->merkle_root, buf);
    deser_u32(&blockheader->timestamp, buf);
    deser_u32(&blockheader->diff_bits, buf);
    deser_u32(&blockheader->nonce, buf);
    deser_varlen(&blockheader->tx_count, buf);
}

void btc_p2p_ser_blockheader(btc_p2p_blockheader *blockheader, cstring* buf)
{
    ser_s32(buf, blockheader->version);
    ser_u256(buf, blockheader->prev_block);
    ser_u256(buf, blockheader->merkle_root);
    ser_u32(buf, blockheader->timestamp);
    ser_u32(buf, blockheader->diff_bits);
    ser_u32(buf, blockheader->nonce);
}

void btc_p2p_blockheader_hash(btc_p2p_blockheader *blockheader, uint8_t *hash_out)
{
    cstring* buf = cstr_new_sz(100);
    btc_p2p_ser_blockheader(blockheader, buf);
    btc_hash((unsigned char *)buf->str, buf->len, hash_out);
    cstr_free(buf, true);
}
