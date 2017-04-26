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

#include <btc/block.h>
#include <btc/blockchain.h>
#include <btc/checkpoints.h>
#include <btc/headersdb.h>
#include <btc/headersdb_file.h>
#include <btc/net.h>
#include <btc/netspv.h>
#include <btc/protocol.h>
#include <btc/serialize.h>
#include <btc/tx.h>
#include <btc/utils.h>

#ifdef _WIN32
#include <getopt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

void btc_net_set_spv(btc_node_group *nodegroup)
{
    nodegroup->parse_cmd_cb = btc_net_spv_pre_cmd;
    nodegroup->postcmd_cb = btc_net_spv_post_cmd;
    nodegroup->handshake_done_cb = btc_net_spv_node_handshake_done;
    nodegroup->node_connection_state_changed_cb = NULL;
    nodegroup->periodic_timer_cb = btc_net_spv_node_timer_callback;
}

btc_spv_client* btc_spv_client_new(const btc_chainparams *params, btc_bool debug)
{
    btc_spv_client* client;
    client = calloc(1, sizeof(*client));

    client->last_getheadermessage = 0;
    client->last_statecheck = 0;
    client->oldest_item_of_interest = time(NULL);
    client->stateflags = SPV_HEADER_SYNC_FLAG;

    client->chainparams = params;

    client->nodegroup = btc_node_group_new(params);
    client->nodegroup->ctx = client;
    client->nodegroup->desired_amount_connected_nodes = 3; /* TODO */

    btc_net_set_spv(client->nodegroup);

    if (debug) {
        client->nodegroup->log_write_cb = net_write_log_printf;
    }

    client->use_checkpoints = true;
    client->headers_db = &btc_headers_db_interface_file;
    client->headers_db_ctx = client->headers_db->init(params, false);

    return client;
}

void btc_spv_client_discover_peers(btc_spv_client* client, const char *ips)
{
    btc_node_group_add_peers_by_ip_or_seed(client->nodegroup, ips);
}

void btc_spv_client_runloop(btc_spv_client* client)
{
    btc_node_group_connect_next_nodes(client->nodegroup);
    btc_node_group_event_loop(client->nodegroup);
}

void btc_spv_client_free(btc_spv_client *client)
{
    if (!client)
        return;

    if (client->headers_db)
    {
        client->headers_db->free(client->headers_db_ctx);
        client->headers_db_ctx = NULL;
    }

    free(client);
}

btc_bool btc_spv_client_load(btc_spv_client *client, const char *file_path)
{
    if (!client)
        return false;

    if (!client->headers_db)
        return false;

    return client->headers_db->load(client->headers_db_ctx, file_path);

}

void btc_net_spv_periodic_statecheck(btc_node *node, uint64_t *now)
{
    /* statecheck logic */
    /* ================ */

    btc_spv_client *client = (btc_spv_client*)node->nodegroup->ctx;

    client->nodegroup->log_write_cb("Statecheck: amount of connected nodes: %d\n", btc_node_group_amount_of_connected_nodes(client->nodegroup, NODE_CONNECTED));

    /* check if we need to sync headers from a different peer */
    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG)
    {
        btc_net_spv_request_headers(client);
    }
    else
    {
        /* headers sync should be done at this point */

    }

    client->last_statecheck = *now;
}

static btc_bool btc_net_spv_node_timer_callback(btc_node *node, uint64_t *now)
{
    btc_spv_client *client = (btc_spv_client*)node->nodegroup->ctx;

    /* check if the node chosen for NODE_HEADERSYNC during SPV_HEADER_SYNC has stalled */
    if ((client->stateflags & SPV_HEADER_SYNC_FLAG) == SPV_HEADER_SYNC_FLAG && ((node->state & NODE_HEADERSYNC) == NODE_HEADERSYNC) && (client->last_getheadermessage > 0) )
    {
        int timedetla = *now - client->last_getheadermessage;
        if (timedetla > 60) /* TODO: TBD timeout */
        {
            /* disconnect the node if we haven't got a header after requesting some with a getheaders message */
            node->state &= ~NODE_HEADERSYNC;
            btc_node_disconnect(node);
            btc_net_spv_request_headers(client);
        }
    }

    if (client->last_statecheck+5 < *now)
    {

        /* do a state check only every <n> seconds */
        btc_net_spv_periodic_statecheck(node, now);
    }

    /* return true = run internal timer logic (ping, disconnect-timeout, etc.) */
    return true;
}

btc_bool btc_net_spv_pre_cmd(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{

    UNUSED(node);
    UNUSED(hdr);
    UNUSED(buf);
    // parse command
    return true;
}

void btc_net_spv_send_getheaders(btc_node *node, vector *blocklocators, uint8_t *hashstop)
{
    UNUSED(node);
    UNUSED(blocklocators);
    UNUSED(hashstop);
}

void btc_net_spv_fill_block_locator(btc_spv_client *client, vector *blocklocators)
{
    if (client->headers_db->getchaintip(client->headers_db_ctx)->height == 0)
    {
        if (client->use_checkpoints) {
            /* jump to checkpoint */
            /* check oldest item of interest and set genesis/checkpoint */

            uint64_t min_timestamp = client->oldest_item_of_interest-(144*10*60); /* ensure we going back ~144 blocks */
            for (int i = (sizeof(btc_mainnet_checkpoint_array) / sizeof(btc_mainnet_checkpoint_array[0]))-1; i >= 0 ; i--)
            {
                if ( btc_mainnet_checkpoint_array[i].timestamp < min_timestamp)
                {
                    uint256 *hash = btc_calloc(1, sizeof(uint256));
                    utils_uint256_sethex((char *)btc_mainnet_checkpoint_array[i].hash, (uint8_t *)hash);
                    vector_add(blocklocators, (void *)hash);

                    if (!client->headers_db->has_checkpoint_start(client->headers_db_ctx)) {
                        client->headers_db->set_checkpoint_start(client->headers_db_ctx, *hash, btc_mainnet_checkpoint_array[i].height);
                    }
                }
            }
        }
        else {
            uint256 *hash = btc_calloc(1, sizeof(uint256));
            memcpy(hash, &client->chainparams->genesisblockhash, sizeof(uint256));
            vector_add(blocklocators, (void *)hash);
            client->nodegroup->log_write_cb("Setting blocklocator with genesis block\n");
        }
    }
    else
    {
        client->headers_db->fill_blocklocator_tip(client->headers_db_ctx, blocklocators);
    }
}

void btc_net_spv_node_request_headers_or_blocks(btc_node *node, btc_bool blocks)
{
    // request next headers
    vector *blocklocators = vector_new(1, free);

    btc_net_spv_fill_block_locator((btc_spv_client *)node->nodegroup->ctx, blocklocators);

    cstring *getheader_msg = cstr_new_sz(256);
    btc_p2p_msg_getheaders(blocklocators, NULL, getheader_msg);

    /* create p2p message */
    cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, (blocks ? "getblocks" : "getheaders"), getheader_msg->str, getheader_msg->len);
    cstr_free(getheader_msg, true);

    /* send message */
    btc_node_send(node, p2p_msg);
    if (!blocks)
        node->state |= NODE_HEADERSYNC;

    /* remember last header request */
    ((btc_spv_client*)node->nodegroup->ctx)->last_getheadermessage = time(NULL);

    /* cleanup */
    vector_free(blocklocators, true);
    cstr_free(p2p_msg, true);
}

btc_bool btc_net_spv_request_headers(btc_spv_client *client)
{
    /* make sure only one node is used for header sync */
    for(size_t i =0;i< client->nodegroup->nodes->len; i++)
    {
        btc_node *check_node = vector_idx(client->nodegroup->nodes, i);
        if (  ( (check_node->state & NODE_HEADERSYNC) == NODE_HEADERSYNC
                 ||
                (check_node->state & NODE_BLOCKSYNC) == NODE_BLOCKSYNC
               )
            &&
            (check_node->state & NODE_CONNECTED) == NODE_CONNECTED)
            return true;
    }

    /* We are not downloading headers at this point */
    /* try to request headers from a peer where the version handshake has been done */
    for(size_t i =0;i< client->nodegroup->nodes->len; i++)
    {
        btc_node *check_node = vector_idx(client->nodegroup->nodes, i);
        if ( ((check_node->state & NODE_CONNECTED) == NODE_CONNECTED) && check_node->version_handshake && check_node->bestknownheight > client->headers_db->getchaintip(client->headers_db_ctx)->height)
        {
            btc_net_spv_node_request_headers_or_blocks(check_node, false);
            return true;
        }
    }

    /* we could not request more headers, need more peers to connect to */
    return false;
}
void btc_net_spv_node_handshake_done(btc_node *node)
{
    btc_net_spv_request_headers((btc_spv_client*)node->nodegroup->ctx);
}

void btc_net_spv_post_cmd(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    btc_spv_client *client = (btc_spv_client *)node->nodegroup->ctx;

    if (strcmp(hdr->command, "inv") == 0 && (node->state & NODE_BLOCKSYNC) == NODE_BLOCKSYNC)
    {
        struct const_buffer original_inv = { buf->p, buf->len };
        uint32_t varlen;
        deser_varlen(&varlen, buf);
        btc_bool onlyblocks = true;

        client->nodegroup->log_write_cb("Get inv request with %d items\n", varlen);

        for (unsigned int i=0;i<varlen;i++)
        {
            uint32_t type;
            deser_u32(&type, buf);
            if (type != BTC_INV_TYPE_BLOCK)
                onlyblocks = false;

            /* skip the hash, we are going to directly use the inv-buffer for the getdata */
            /* this means we don't support invs contanining blocks and txns as a getblock answer */
            deser_skip(buf, 32);
        }

        if (onlyblocks)
        {
            /* request the blocks */
            client->nodegroup->log_write_cb("Requesting %d blocks\n", varlen);
            cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, BTC_MSG_GETDATA, original_inv.p, original_inv.len);
            btc_node_send(node, p2p_msg);
            cstr_free(p2p_msg, true);

            if (varlen >= 500) {
                /* directly request more blocks */
                /* not sure if this is clever if we want to download as ex. the complete chain */
                btc_net_spv_node_request_headers_or_blocks(node, true);
            }
        }
        else if (varlen > 1) {
            client->nodegroup->log_write_cb("Error inv mixed type\n");
        }
    }
    if (strcmp(hdr->command, "block") == 0)
    {
        btc_bool connected;
        btc_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);
        /* deserialize the p2p header */
        if (!pindex) {
            /* deserialization failed */
            return;
        }

        uint32_t amount_of_txs;
        if (!deser_varlen(&amount_of_txs, buf)) {
            /* deserialization transaction varint failed */
            return;
        }

        /* for now, only scan if the block could be connected on top */
        if (connected) {
            printf("Dummy: parsing %d tx(s) from block at height: %d\n", amount_of_txs, pindex->height);

            size_t consumedlength = 0;
            for (unsigned int i=0;i<amount_of_txs;i++)
            {
                btc_tx* tx = btc_tx_new();
                btc_tx_deserialize(buf->p, buf->len, tx, &consumedlength);
                deser_skip(buf, consumedlength);

                /* send info to possible callback */
                if (client->sync_transaction)
                    client->sync_transaction(client, tx, pindex);

                btc_tx_free(tx);
            }
        }
        else {
            fprintf(stderr, "Could not connect block on top of the chain\n");
        }
    }
    if (strcmp(hdr->command, "headers") == 0)
    {
        uint32_t amount_of_headers;
        if (!deser_varlen(&amount_of_headers, buf)) return;
        client->nodegroup->log_write_cb("Got %d headers from node %d\n", amount_of_headers, node->nodeid);

        unsigned int connected_headers = 0;
        for (unsigned int i=0;i<amount_of_headers;i++)
        {
            btc_bool connected;
            btc_blockindex *pindex = client->headers_db->connect_hdr(client->headers_db_ctx, buf, false, &connected);
            /* deserialize the p2p header */
            if (!pindex)
            {
                client->nodegroup->log_write_cb("Header deserialization failed (node %d)\n", node->nodeid);
                return;
            }

            /* skip tx count */
            if (!deser_skip(buf, 1)) {
                client->nodegroup->log_write_cb("Header deserialization (tx count skip) failed (node %d)\n", node->nodeid);
                return;
            }

            if (!connected)
            {
                /* error, header sequence missmatch
                   mark node as missbehaving */
                client->nodegroup->log_write_cb("Got invalid headers (not in sequence) from node %d\n", node->nodeid);
                node->state &= ~NODE_HEADERSYNC;
                btc_node_missbehave(node);

                /* see if we can fetch headers from a different peer */
                btc_net_spv_request_headers(client);
            }
            else {
                connected_headers++;
                if (pindex->header.timestamp > client->oldest_item_of_interest-3600-(144*10*60)) {

                    /* we should start loading block from this point */
                    client->stateflags &= ~SPV_HEADER_SYNC_FLAG;
                    client->stateflags |= SPV_FULLBLOCK_SYNC_FLAG;
                    node->state &= ~NODE_HEADERSYNC;
                    node->state |= NODE_BLOCKSYNC;

                    client->nodegroup->log_write_cb("start loading block from node %d at height %d at time: %ld\n", node->nodeid, client->headers_db->getchaintip(client->headers_db_ctx)->height, client->headers_db->getchaintip(client->headers_db_ctx)->header.timestamp);
                    btc_net_spv_node_request_headers_or_blocks(node, true);

                    /* ignore the rest of the headers */
                    /* we are going to request blocks now */
                    break;
                }
            }
        }
        btc_blockindex *chaintip = client->headers_db->getchaintip(client->headers_db_ctx);

        client->nodegroup->log_write_cb("Connected %d headers\n", connected_headers);
        client->nodegroup->log_write_cb("Chaintip at height %d\n", chaintip->height);

        /* call the header message processed callback and allow canceling the further logic commands */
        if (client->header_message_processed && client->header_message_processed(client, node, chaintip) == false)
            return;

        if (amount_of_headers == MAX_HEADERS_RESULTS && ((node->state & NODE_BLOCKSYNC) != NODE_BLOCKSYNC))
        {
            /* peer sent maximal amount of headers, very likely, there will be more */
            time_t lasttime = chaintip->header.timestamp;
            client->nodegroup->log_write_cb("chain size: %d, last time %s", chaintip->height, ctime(&lasttime));
            btc_net_spv_node_request_headers_or_blocks(node, false);
        }
        else
        {
            /* headers download seems to be completed */
            /* we should have switched to block request if the oldest_item_of_interest was set correctly */
        }
    }
}
