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

#ifdef __cplusplus
extern "C" {
#endif

#include "btc.h"
#include <logdb/logdb.h>
#include <logdb/logdb_rec.h>

typedef struct btc_spv_client_ {
    logdb_log_db* headerdb;
} btc_spv_client;


btc_spv_client* btc_spv_client_new();
void btc_spv_client_free(btc_spv_client* client);
btc_bool btc_spv_client_load(btc_spv_client* client, const char* file_path, enum logdb_error* error);

/* set the nodegroup SPV callbacks */
void btc_net_set_spv(btc_node_group* nodegroup);

/* callback function for pre-command logic
       returns true to allow executig base message logic (version/verack, ping/pong)
     */
btc_bool btc_net_spv_pre_cmd(btc_node* node, btc_p2p_msg_hdr* hdr, struct const_buffer* buf);

/* callback function to inject SPV message logic */
void btc_net_spv_post_cmd(btc_node* node, btc_p2p_msg_hdr* hdr, struct const_buffer* buf);

/* callback function to dispatch messages once version/verack handshake has been done */
void btc_net_spv_node_handshake_done(btc_node* node);

void btc_net_spv_send_getheaders(btc_node* node, vector* blocklocators, uint256 hashstop);

void btc_net_spv_get_peers_from_dns(const char* seed, vector* ips_out, int family);

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_NETSPV_H__
