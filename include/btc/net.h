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


#ifndef __LIBBTC_NET_H__
#define __LIBBTC_NET_H__

#include "btc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <event2/event.h>
#include <btc/chain.h>
#include <btc/buffer.h>
#include <btc/cstr.h>
#include "vector.h"
#include "protocol.h"

static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 2 * 1024 * 1024;
static const unsigned int P2P_MESSAGE_CHUNK_SIZE = 4096;

enum NODE_STATE {
    NODE_CONNECTING	= (1 << 0),
    NODE_CONNECTED	= (1 << 1),
    NODE_ERRORED	= (1 << 2),
    NODE_TIMEOUT	= (1 << 3),
    NODE_HEADERSYNC	= (1 << 4),
};

struct btc_node_;
typedef struct btc_node_group_
{
    void *ctx;
    struct event_base *event_base;
    vector *nodes;
    char clientstr[1024];
    int desired_amount_connected_nodes;
    const btc_chain *chainparams;
    btc_bool (*parse_cmd_cb)(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf);
    void (*postcmd_cb)(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf);
    void (*node_connection_state_changed_cb)(struct btc_node_ *node);
    void (*handshake_done_cb)(struct btc_node_ *node);
} btc_node_group;

enum {
    NODE_CONNECTIONSTATE_DISCONNECTED = 0,
    NODE_CONNECTIONSTATE_CONNECTING = 5,
    NODE_CONNECTIONSTATE_CONNECTED = 50,
    NODE_CONNECTIONSTATE_ERRORED = 100,
    NODE_CONNECTIONSTATE_ERRORED_TIMEOUT = 101,
};

typedef struct btc_node_
{
    struct sockaddr addr;
    struct bufferevent *event_bev;
    btc_node_group *nodegroup;
    int nodeid;

    cstring *recvBuffer;
    uint64_t nonce;
    uint64_t services;
    uint32_t state;
    int      missbehavescore;
    btc_bool version_handshake;
} btc_node;

LIBBTC_API btc_node* btc_node_new();
LIBBTC_API void btc_node_free(btc_node *group);
LIBBTC_API btc_bool btc_node_setaddr_str(btc_node *node, const char *str_addr);

LIBBTC_API btc_node_group* btc_node_group_new(btc_chain *chainparams);
LIBBTC_API void btc_node_group_free(btc_node_group *group);
LIBBTC_API void btc_node_group_event_loop(btc_node_group *group);
LIBBTC_API void btc_node_group_add_node(btc_node_group *group, btc_node *node);
LIBBTC_API btc_bool btc_node_group_connect_next_nodes(btc_node_group *group);
LIBBTC_API int btc_node_group_amount_of_connected_nodes(btc_node_group *group);

LIBBTC_API void btc_node_connection_state_changed(btc_node *node);
LIBBTC_API void btc_node_send(btc_node *node, cstring *data);
LIBBTC_API void btc_node_send_version(btc_node *node);
LIBBTC_API int btc_node_parse_message(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf);
#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_NET_H__
