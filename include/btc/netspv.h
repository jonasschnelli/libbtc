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

#ifndef __LIBBTC_NETSPV_H__
#define __LIBBTC_NETSPV_H__

#include "btc.h"
#include <btc/blockchain.h>
#include <btc/headersdb.h>
#include <btc/tx.h>

#ifdef __cplusplus
extern "C" {
#endif

enum SPV_CLIENT_STATE {
    SPV_HEADER_SYNC_FLAG        = (1 << 0),
    SPV_FULLBLOCK_SYNC_FLAG	    = (1 << 1),
};

typedef struct btc_spv_client_
{
    btc_node_group *nodegroup;
    uint64_t last_getheadermessage;
    uint64_t oldest_item_of_interest; /* a.k.a. oldest key birthday */
    btc_bool use_checkpoints; /* if false, the client will create a headers chain starting from genesis */
    const btc_chainparams *chainparams;
    int stateflags;
    uint64_t last_statecheck;



    void *headers_db_ctx; /* flexible headers db context */
    const btc_headers_db_interface *headers_db; /* headers db interface */

    /* callbacks */
    /* ========= */

    /* callback when a block(header) was connected */
    void (*header_connected)(struct btc_spv_client_ *client);

    /* callback when the header message has been processed */
    /* return false will abort further logic (like continue loading headers, etc.) */
    btc_bool (*header_message_processed)(struct btc_spv_client_ *client, btc_node *node, btc_blockindex *newtip);

    /* callback, executed on each transaction (when getting a block, merkle-block txns or inv txns) */
    void (*sync_transaction)(struct btc_spv_client_ *client, btc_tx *tx, btc_blockindex *blockindex);
} btc_spv_client;


btc_spv_client* btc_spv_client_new(const btc_chainparams *params, btc_bool debug);
void btc_spv_client_free(btc_spv_client *client);
btc_bool btc_spv_client_load(btc_spv_client *client, const char *file_path);

void btc_spv_client_discover_peers(btc_spv_client *client, const char *ips);
void btc_spv_client_runloop(btc_spv_client *client);

/* set the nodegroup SPV callbacks */
void btc_net_set_spv(btc_node_group *nodegroup);

/* callback function for pre-command logic
   returns true to allow executig base message logic (version/verack, ping/pong)
 */
btc_bool btc_net_spv_pre_cmd(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf);

/* try to request headers from a single node in the nodegroup */
btc_bool btc_net_spv_request_headers(btc_spv_client *client);

/* callback function triggered periodically */
static btc_bool btc_net_spv_node_timer_callback(btc_node *node, uint64_t *now);

/* callback function to inject SPV message logic */
void btc_net_spv_post_cmd(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf);

/* callback function to dispatch messages once version/verack handshake has been done */
void btc_net_spv_node_handshake_done(btc_node *node);

void btc_net_spv_send_getheaders(btc_node *node, vector *blocklocators, uint8_t *hashstop);

void btc_net_spv_get_peers_from_dns(const char *seed, vector *ips_out, int family);

void btc_spv_find_header_by_hash(btc_spv_client *client, const uint256 hash);

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_NETSPV_H__
