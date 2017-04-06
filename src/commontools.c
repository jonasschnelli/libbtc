/**********************************************************************
 * Copyright (c) 2016 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <btc/base58.h>
#include <btc/bip32.h>
#include <btc/ecc.h>
#include <btc/ecc_key.h>
#include <btc/net.h>
#include <btc/random.h>
#include <btc/serialize.h>
#include <btc/tx.h>
#include <btc/utils.h>

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

btc_bool address_from_pubkey(const btc_chainparams* chain, const char *pubkey_hex, char *address)
{
    if (!pubkey_hex || strlen(pubkey_hex) != 66)
        return false;

    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);
    pubkey.compressed = 1;

    size_t outlen = 0;
    utils_hex_to_bin(pubkey_hex, pubkey.pubkey, strlen(pubkey_hex), (int *)&outlen);
    assert(btc_pubkey_is_valid(&pubkey) == 1);

    uint8_t hash160[21];
    hash160[0] = chain->b58prefix_pubkey_address;
    btc_pubkey_get_hash160(&pubkey, hash160+1);

    btc_base58_encode_check(hash160, 21, address, 98);

    return true;
}

btc_bool pubkey_from_privatekey(const btc_chainparams* chain, const char *privkey_wif, char *pubkey_hex, size_t *sizeout)
{
    uint8_t privkey_data[strlen(privkey_wif)];
    size_t outlen = 0;
    outlen = btc_base58_decode_check(privkey_wif, privkey_data, sizeof(privkey_data));
    if (privkey_data[0] != chain->b58prefix_secret_address)
        return false;

    btc_key key;
    btc_privkey_init(&key);
    memcpy(key.privkey, privkey_data+1, 32);

    btc_pubkey pubkey;
    btc_pubkey_init(&pubkey);
    assert(btc_pubkey_is_valid(&pubkey) == 0);
    btc_pubkey_from_key(&key, &pubkey);
    btc_privkey_cleanse(&key);

    btc_pubkey_get_hex(&pubkey, pubkey_hex, sizeout);
    btc_pubkey_cleanse(&pubkey);
    
    return true;
}

btc_bool gen_privatekey(const btc_chainparams* chain, char *privkey_wif, size_t strsize_wif, char *privkey_hex_or_null)
{
    uint8_t pkeybase58c[34];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */

    btc_key key;
    btc_privkey_init(&key);
    btc_privkey_gen(&key);
    memcpy(&pkeybase58c[1], key.privkey, BTC_ECKEY_PKEY_LENGTH);
    assert(btc_base58_encode_check(pkeybase58c, 34, privkey_wif, strsize_wif) != 0);

    // also export the hex privkey if use had passed in a valid pointer
    // will always export 32 bytes
    if (privkey_hex_or_null != NULL)
        utils_bin_to_hex(key.privkey, BTC_ECKEY_PKEY_LENGTH, privkey_hex_or_null);
    btc_privkey_cleanse(&key);
    return true;
}

btc_bool hd_gen_master(const btc_chainparams* chain, char *masterkeyhex, size_t strsize)
{
    btc_hdnode node;
    uint8_t seed[32];
    random_bytes(seed, 32, true);
    btc_hdnode_from_seed(seed, 32, &node);
    memset(seed, 0, 32);
    btc_hdnode_serialize_private(&node, chain, masterkeyhex, strsize);
    memset(&node, 0, sizeof(node));
    return true;
}

btc_bool hd_print_node(const btc_chainparams* chain, const char *nodeser)
{
    btc_hdnode node;
    if (!btc_hdnode_deserialize(nodeser, chain, &node))
        return false;

    size_t strsize = 128;
    char str[strsize];
    btc_hdnode_get_p2pkh_address(&node, chain, str, strsize);

    printf("ext key: %s\n", nodeser);

    size_t privkey_wif_size_bin = 34;
    uint8_t pkeybase58c[privkey_wif_size_bin];
    pkeybase58c[0] = chain->b58prefix_secret_address;
    pkeybase58c[33] = 1; /* always use compressed keys */
    size_t privkey_wif_size = 128;
    char privkey_wif[privkey_wif_size];
    memcpy(&pkeybase58c[1], node.private_key, BTC_ECKEY_PKEY_LENGTH);
    assert(btc_base58_encode_check(pkeybase58c, privkey_wif_size_bin, privkey_wif, privkey_wif_size) != 0);
    printf("privatekey WIF: %s\n", privkey_wif);

    printf("depth: %d\n", node.depth);
    printf("p2pkh address: %s\n", str);

    if (!btc_hdnode_get_pub_hex(&node, str, &strsize))
        return false;
    printf("pubkey hex: %s\n", str);

    strsize = 128;
    btc_hdnode_serialize_public(&node, chain, str, strsize);
    printf("extended pubkey: %s\n", str);
    return true;
}

btc_bool hd_derive(const btc_chainparams* chain, const char *masterkey, const char *keypath, char *extkeyout, size_t extkeyout_size)
{
    btc_hdnode node, nodenew;
    if (!btc_hdnode_deserialize(masterkey, chain, &node))
        return false;

    //check if we only have the publickey
    bool pubckd = !btc_hdnode_has_privkey(&node);

    //derive child key, use pubckd or privckd
    btc_hd_generate_key(&nodenew, keypath, pubckd ? node.public_key : node.private_key, node.chain_code, pubckd);

    if (pubckd)
        btc_hdnode_serialize_public(&nodenew, chain, extkeyout, extkeyout_size);
    else
        btc_hdnode_serialize_private(&nodenew, chain, extkeyout, extkeyout_size);
    return true;
}

struct broadcast_ctx {
    const btc_tx *tx;
    int connected_to_peers;
    int max_peers_to_connect;
    int max_peers_to_inv;
    int inved_to_peers;
    int getdata_from_peers;
    int found_on_non_inved_peers;
};

static int broadcast_default_write_log(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("DEBUG :");
    vprintf(format, args);
    va_end(args);
    return 1;
}

static btc_bool broadcast_timer_cb(btc_node *node, uint64_t *now)
{
    broadcast_default_write_log("timer node %d, delta: %d\n", node->nodeid, (now - node->time_started_con ));
    if (node->time_started_con + 15 < *now)
        btc_node_disconnect(node);

    if ((node->hints & (1 << 1)) == (1 << 1))
    {
        btc_node_disconnect(node);
    }

    if ((node->hints & (1 << 2)) == (1 << 2))
    {
        btc_node_disconnect(node);
    }

    /* return true = run internal timer logic (ping, disconnect-timeout, etc.) */
    return true;
}

void broadcast_handshake_done(struct btc_node_ *node)
{
    struct broadcast_ctx *ctx = (struct broadcast_ctx  *)node->nodegroup->ctx;
    ctx->connected_to_peers++;

    if (ctx->inved_to_peers >= ctx->max_peers_to_inv) {
        return;
    }

    /* create a INV */
    cstring *inv_msg_cstr = cstr_new_sz(256);
    btc_p2p_inv_msg inv_msg;
    memset(&inv_msg, 0, sizeof(inv_msg));

    uint8_t hash[32];
    btc_tx_hash(ctx->tx, hash);
    btc_p2p_msg_inv_init(&inv_msg, BTC_INV_TYPE_TX, hash);

    /* serialize the inv count (1) */
    ser_varlen(inv_msg_cstr, 1);
    btc_p2p_msg_inv_ser(&inv_msg, inv_msg_cstr);

    cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, BTC_MSG_INV, inv_msg_cstr->str, inv_msg_cstr->len);
    cstr_free(inv_msg_cstr, true);
    btc_node_send(node, p2p_msg);
    cstr_free(p2p_msg, true);

    /* set hint bit 0 == inv sent */
    node->hints |= (1 << 0);
    ctx->inved_to_peers++;
}

void broadcast_post_cmd(struct btc_node_ *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf) {
    struct broadcast_ctx *ctx = (struct broadcast_ctx  *)node->nodegroup->ctx;
    if (strcmp(hdr->command, BTC_MSG_INV) == 0)
    {
        /* hash the tx */
        /* TODO: cache the hash */
        uint8_t hash[32];
        btc_tx_hash(ctx->tx, hash);

        //  decompose
        uint32_t vsize;
        if (!deser_varlen(&vsize, buf)) { btc_node_missbehave(node); return; };
        for (unsigned int i=0;i<vsize;i++)
        {
            btc_p2p_inv_msg inv_msg;
            if (!btc_p2p_msg_inv_deser(&inv_msg, buf)) { btc_node_missbehave(node); return; }
            if (memcmp(hash, inv_msg.hash, 32) == 0) {
                // txfound
                /* set hint bit 2 == tx found on peer*/
                node->hints |= (1 << 2);
                printf("node %d has the tx\n", node->nodeid);
                ctx->found_on_non_inved_peers++;
                printf("tx successfully seen on node %d\n", node->nodeid);
            }
        }
    }
    else if (strcmp(hdr->command, BTC_MSG_GETDATA) == 0)
    {
        ctx->getdata_from_peers++;
        //only allow a single object in getdata for the broadcaster
        uint32_t vsize;
        if (!deser_varlen(&vsize, buf) || vsize!=1) { btc_node_missbehave(node); return; }

        btc_p2p_inv_msg inv_msg;
        memset(&inv_msg, 0, sizeof(inv_msg));
        if (!btc_p2p_msg_inv_deser(&inv_msg, buf) || inv_msg.type != BTC_INV_TYPE_TX) { btc_node_missbehave(node); return; };

        /* send the tx */
        cstring* tx_ser = cstr_new_sz(1024);
        btc_tx_serialize(tx_ser, ctx->tx);
        cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, BTC_MSG_TX, tx_ser->str, tx_ser->len);
        cstr_free(tx_ser, true);
        btc_node_send(node, p2p_msg);
        cstr_free(p2p_msg, true);

        /* set hint bit 1 == tx sent */
        node->hints |= (1 << 1);

        printf("tx successfully sent to node %d\n", node->nodeid);
    }
}

btc_bool broadcast_tx(const btc_chainparams* chain, const btc_tx *tx, const char *ips)
{
    struct broadcast_ctx ctx;
    ctx.tx = tx;
    ctx.max_peers_to_inv = 2;
    ctx.found_on_non_inved_peers = 0;
    ctx.getdata_from_peers = 0;
    ctx.inved_to_peers = 0;
    ctx.connected_to_peers = 0;
    ctx.max_peers_to_connect = 6;

    /* create a node group */
    btc_node_group* group = btc_node_group_new(chain);
    group->desired_amount_connected_nodes = ctx.max_peers_to_connect;
    group->ctx = &ctx;

    /* set the timeout callback */
    group->periodic_timer_cb = broadcast_timer_cb;

    /* set a individual log print function */
    group->log_write_cb = broadcast_default_write_log;
    group->postcmd_cb = broadcast_post_cmd;
    group->handshake_done_cb = broadcast_handshake_done;

    if (ips == NULL) {
        /* === DNS QUERY === */
        /* get a couple of peers from a seed */
        vector *ips_dns = vector_new(10, free);
        const btc_dns_seed seed = chain->dnsseeds[0];
        if (strlen(seed.domain) == 0)
        {
            return -1;
        }
        /* todo: make sure we have enought peers, eventually */
        /* call another seeder */
        btc_get_peers_from_dns(seed.domain, ips_dns, chain->default_port, AF_INET);
        for (unsigned int i = 0; i<ips_dns->len; i++)
        {
            char *ip = (char *)vector_idx(ips_dns, i);

            /* create a node */
            btc_node *node = btc_node_new();
            if (btc_node_set_ipport(node, ip) > 0) {
                /* add the node to the group */
                btc_node_group_add_node(group, node);
            }
        }
        vector_free(ips_dns, true);
    }
    else {
        // add comma seperated ips (nodes)
        char working_str[64];
        memset(working_str, 0, sizeof(working_str));
        size_t offset = 0;
        for(unsigned int i=0;i<=strlen(ips);i++)
        {
            if (i == strlen(ips) || ips[i] == ',') {
                btc_node *node = btc_node_new();
                if (btc_node_set_ipport(node, working_str) > 0) {
                    btc_node_group_add_node(group, node);
                }
                offset = 0;
                memset(working_str, 0, sizeof(working_str));
            }
            else if (ips[i] != ' ' && offset < sizeof(working_str)) {
                working_str[offset]=ips[i];
                offset++;
            }
        }
    }


    /* connect to the next node */
    btc_node_group_connect_next_nodes(group);

    /* start the event loop */
    btc_node_group_event_loop(group);

    /* cleanup */
    btc_node_group_free(group); //will also free the nodes structures from the heap

    printf("Result:\n=============\n");
    printf("Max peers to connect to: %d\n", ctx.max_peers_to_connect);
    printf("Connected to peers: %d\n", ctx.connected_to_peers);
    printf("Informed peers: %d\n", ctx.inved_to_peers);
    printf("Requested from peers: %d\n", ctx.getdata_from_peers);
    printf("Seen on other peers: %d\n", ctx.found_on_non_inved_peers);
    return 1;
}
