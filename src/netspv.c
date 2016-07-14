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

#include <btc/net.h>
#include <btc/netspv.h>
#include <btc/protocol.h>
#include <btc/serialize.h>
#include <btc/utils.h>

#include <event2/event.h>

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>

/* static logdb interface */
void btc_spv_client_headerdb_append(void* ctx, logdb_bool load_phase, logdb_record *rec);
static logdb_memmapper btc_spv_headerdb_mapper = {
    btc_spv_client_headerdb_append,
    NULL,
    NULL,
    NULL,
    NULL
};

typedef struct btc_spv_chain_header_ {
    uint32_t height;
    uint8_t hash[32];
    btc_p2p_blockheader header;
    struct btc_spv_chain_header_ *next_header;
    struct btc_spv_chain_header_ *prev_header;
} btc_spv_chain_header;

static btc_spv_chain_header genesis;
static btc_spv_chain_header *headerschaintip = &genesis;

void btc_get_default_datadir(cstring *path_out)
{
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Bitcoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Bitcoin
    // Mac: ~/Library/Application Support/Bitcoin
    // Unix: ~/.bitcoin
#ifdef WIN32
    // Windows
    char* homedrive = getenv("HOMEDRIVE");
    char* homepath = getenv("HOMEDRIVE");
    cstr_append_buf(path_out, homedrive, strlen(homedrive));
    cstr_append_buf(path_out, homepath, strlen(homepath));
#else
    char* home = getenv("HOME");
    if (home == NULL || strlen(home) == 0)
        cstr_append_c(path_out, '/');
    else
        cstr_append_buf(path_out, home, strlen(home));
#ifdef __APPLE__
    // Mac
    char *osx_home = "/Library/Application Support/Bitcoin";
    cstr_append_buf(path_out, osx_home, strlen(osx_home));
#else
    // Unix
    char *posix_home = "/.bitcoin";
    cstr_append_buf(path_out, posix_home, strlen(posix_home));
#endif
#endif
}

btc_spv_client* btc_spv_client_new()
{
    btc_spv_client* client;
    client = calloc(1, sizeof(*client));
    client->headerdb = logdb_new();
    logdb_set_memmapper(client->headerdb, &btc_spv_headerdb_mapper, client);

    return client;
}

void btc_spv_client_headerdb_append(void* ctx, logdb_bool load_phase, logdb_record *rec)
{
    btc_spv_client* client = (btc_spv_client*)ctx;
    if (load_phase)
    {
        static const char *headerkey = "header";
        if (rec->key->len > strlen(headerkey))
        {
            uint8_t *hash = (uint8_t *)rec->key->str+strlen(headerkey);

            /* heap alloc a new chain header struct */
            btc_spv_chain_header *chainheader = calloc(1, sizeof(btc_spv_chain_header));
            chainheader->height = headerschaintip->height+1;

            /* deserialize the p2p header */
            struct const_buffer buf = {rec->value->str, rec->value->len};
            btc_p2p_deser_blockheader(&chainheader->header, &buf);
            btc_p2p_blockheader_hash(&chainheader->header, (uint8_t *)&chainheader->hash);

            /* connect the linked list */
            if (headerschaintip->height == 0 || memcmp(chainheader->header.prev_block, headerschaintip->hash, 32) == 0)
            {
                // TODO: check claimed PoW
                headerschaintip->next_header = chainheader;
                chainheader->next_header = NULL;
                chainheader->prev_header = headerschaintip;
                headerschaintip = headerschaintip->next_header;
            }
        }
    }
}

void btc_spv_client_free(btc_spv_client *client)
{
    if (!client)
        return;

    if (client->headerdb)
    {
        logdb_free(client->headerdb);
        client->headerdb = NULL;
    }

    free(client);
}

btc_bool btc_spv_client_load(btc_spv_client *client, const char *file_path, enum logdb_error *error)
{
    if (!client)
        return false;

    if (!client->headerdb)
        return false;

    if (client->headerdb->file)
    {
        *error = LOGDB_ERROR_FILE_ALREADY_OPEN;
        return false;
    }

    char *file_path_local = (char *)file_path;
    cstring *path_ret = cstr_new_sz(1024);
    if (!file_path)
    {
        btc_get_default_datadir(path_ret);
        char *filename = "/header.logdb";
        cstr_append_buf(path_ret, filename, strlen(filename));
        cstr_append_c(path_ret, 0);
        file_path_local = path_ret->str;
    }

    struct stat buffer;
    btc_bool create = true;
    if (stat(file_path_local, &buffer) == 0)
        create = false;

    enum logdb_error db_error = 0;
    if (!logdb_load(client->headerdb, file_path_local, create, &db_error))
    {
        cstr_free(path_ret, true);
        *error = db_error;
        return false;
    }

    cstr_free(path_ret, true);
    return true;
}

btc_bool btc_net_spv_pre_cmd(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    // parse command
    return true;
}

void btc_net_spv_send_getheaders(btc_node *node, vector *blocklocators, uint8_t *hashstop)
{

}

void btc_net_spv_fill_block_locator(vector *blocklocators)
{
    btc_spv_chain_header *scan_tip = headerschaintip;
    for(int i = 0; i<10;i++)
    {
        vector_add(blocklocators, (void *)scan_tip->hash);
        if (scan_tip->prev_header)
            scan_tip = scan_tip->prev_header;
        else
            break;
    }
}

void btc_net_spv_node_request_headers(btc_node *node)
{
    // request next headers
    vector *blocklocators = vector_new(1, NULL);

    btc_net_spv_fill_block_locator(blocklocators);

    cstring *getheader_msg = cstr_new_sz(256);
    btc_p2p_msg_getheaders(blocklocators, NULL, getheader_msg);

    /* create p2p message */
    cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "getheaders", getheader_msg->str, getheader_msg->len);
    cstr_free(getheader_msg, true);

    /* send message */
    node->state |= NODE_HEADERSYNC;
    btc_node_send(node, p2p_msg);

    /* cleanup */
    vector_free(blocklocators, true);
    cstr_free(p2p_msg, true);
}
void btc_net_spv_node_handshake_done(btc_node *node)
{
    /* make sure only one node is used for header sync */
    for(size_t i =0;i< node->nodegroup->nodes->len; i++)
    {
        btc_node *check_node = vector_idx(node->nodegroup->nodes, i);
        if ((check_node->state & NODE_HEADERSYNC) == NODE_HEADERSYNC)
            return;
    }
    btc_net_spv_node_request_headers(node);
}

void btc_net_spv_post_cmd(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    btc_spv_client *client = (btc_spv_client *)node->nodegroup->ctx;

    if (strcmp(hdr->command, "headers") == 0)
    {
        uint32_t varlen;
        deser_varlen(&varlen, buf);

        for (unsigned int i=0;i<varlen;i++)
        {
            /* heap alloc a new chain header struct */
            btc_spv_chain_header *chainheader = calloc(1, sizeof(btc_spv_chain_header));
            chainheader->height = headerschaintip->height+1;

            /* deserialize the p2p header */
            btc_p2p_deser_blockheader(&chainheader->header, buf);
            btc_p2p_blockheader_hash(&chainheader->header, (uint8_t *)&chainheader->hash);

            /* connect the linked list */
            if (headerschaintip->height == 0 || memcmp(chainheader->header.prev_block, headerschaintip->hash, 32) == 0)
            {
                // TODO: check claimed PoW
                headerschaintip->next_header = chainheader;
                chainheader->next_header = NULL;
                chainheader->prev_header = headerschaintip;
                headerschaintip = headerschaintip->next_header;

                // store in db
                cstring *key = cstr_new_sz(100);
                char *keyprefix = "header";
                cstr_append_buf(key, keyprefix, strlen(keyprefix));
                cstr_append_buf(key, headerschaintip->hash, 32);

                struct buffer buf_key = {key->str, key->len};

                cstring *header_ser = cstr_new_sz(100);
                btc_p2p_ser_blockheader(&headerschaintip->header, header_ser);
                struct buffer buf_val = {header_ser->str, header_ser->len};
                logdb_append(client->headerdb, &buf_key, &buf_val);

                cstr_free(key, true);
                cstr_free(header_ser, true);
            }
            else
            {
                /* error, header sequence missmatch
                   mark node as missbehaving */
                /* TODO */
                int error = 1;
            }
        }
        logdb_flush(client->headerdb);
        if (varlen == MAX_HEADERS_RESULTS)
        {
            /* peer sent maximal amount of headers, very likely, there will be more */
            printf("chain size: %d\n", headerschaintip->height);
            btc_net_spv_node_request_headers(node);
        }
        else
        {
            /* headers download seems to be completed */
            int completed = 1;
        }
    }
}

void btc_net_spv_get_peers_from_dns(const char *seed, vector *ips_out, int family)
{
    char *def_port = "8333";
    struct evutil_addrinfo hints, *aiTrav = NULL, *aiRes = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int expect_err5 = evutil_getaddrinfo((seed ? seed : "seed.bitcoin.jonasschnelli.ch"), def_port, &hints, &aiRes);
    aiTrav = aiRes;
    while (aiTrav != NULL)
    {
        if (aiTrav->ai_family == AF_INET)
        {
            assert(aiTrav->ai_addrlen >= sizeof(struct sockaddr_in));
            char *ip = inet_ntoa(((struct sockaddr_in*)(aiTrav->ai_addr))->sin_addr);
            char *ipCpy = malloc(strlen(ip)+strlen(def_port)+2);
            strcpy(ipCpy, ip);
            memcpy(ipCpy+strlen(ip), ":", 1);
            memcpy(ipCpy+strlen(ip)+1, def_port, strlen(def_port));
            int len = strlen(def_port);
            *(ipCpy+strlen(ip)+1+strlen(def_port)) = 0;
            vector_add(ips_out, ipCpy);
        }

        if (aiTrav->ai_family == AF_INET6)
        {
            assert(aiTrav->ai_addrlen >= sizeof(struct sockaddr_in6));
            struct sockaddr_in6* s6 = (struct sockaddr_in6*) aiTrav->ai_addr;
            //vIP.push_back(CNetAddr(s6->sin6_addr, s6->sin6_scope_id));
        }

        aiTrav = aiTrav->ai_next;
    }
}

void btc_net_set_spv(btc_node_group *nodegroup)
{
    genesis.height = 0;
    genesis.prev_header = NULL;
    genesis.next_header = NULL;
    memcpy(&genesis.hash, nodegroup->chainparams->genesisblockhash, 32);
    nodegroup->parse_cmd_cb = btc_net_spv_pre_cmd;
    nodegroup->postcmd_cb = btc_net_spv_post_cmd;
    nodegroup->handshake_done_cb = btc_net_spv_node_handshake_done;
    nodegroup->node_connection_state_changed_cb = NULL;
}
