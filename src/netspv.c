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

/* blockchain checkpoints - these are also used as starting points for partial chain downloads, so they need to be at
   difficulty transition boundaries in order to verify the block difficulty at the immediately following transition
*/
static const struct { uint32_t height; const char *hash; uint32_t timestamp; uint32_t target; } checkpoint_array[] = {
    {      0, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", 1231006505, 0x1d00ffff },
    {  20160, "000000000f1aef56190aee63d33a373e6487132d522ff4cd98ccfc96566d461e", 1248481816, 0x1d00ffff },
    {  40320, "0000000045861e169b5a961b7034f8de9e98022e7a39100dde3ae3ea240d7245", 1266191579, 0x1c654657 },
    {  60480, "000000000632e22ce73ed38f46d5b408ff1cff2cc9e10daaf437dfd655153837", 1276298786, 0x1c0eba64 },
    {  80640, "0000000000307c80b87edf9f6a0697e2f01db67e518c8a4d6065d1d859a3a659", 1284861847, 0x1b4766ed },
    { 100800, "000000000000e383d43cc471c64a9a4a46794026989ef4ff9611d5acb704e47a", 1294031411, 0x1b0404cb },
    { 120960, "0000000000002c920cf7e4406b969ae9c807b5c4f271f490ca3de1b0770836fc", 1304131980, 0x1b0098fa },
    { 141120, "00000000000002d214e1af085eda0a780a8446698ab5c0128b6392e189886114", 1313451894, 0x1a094a86 },
    { 161280, "00000000000005911fe26209de7ff510a8306475b75ceffd434b68dc31943b99", 1326047176, 0x1a0d69d7 },
    { 181440, "00000000000000e527fc19df0992d58c12b98ef5a17544696bbba67812ef0e64", 1337883029, 0x1a0a8b5f },
    { 201600, "00000000000003a5e28bef30ad31f1f9be706e91ae9dda54179a95c9f9cd9ad0", 1349226660, 0x1a057e08 },
    { 221760, "00000000000000fc85dd77ea5ed6020f9e333589392560b40908d3264bd1f401", 1361148470, 0x1a04985c },
    { 241920, "00000000000000b79f259ad14635739aaf0cc48875874b6aeecc7308267b50fa", 1371418654, 0x1a00de15 },
    { 262080, "000000000000000aa77be1c33deac6b8d3b7b0757d02ce72fffddc768235d0e2", 1381070552, 0x1916b0ca },
    { 282240, "0000000000000000ef9ee7529607286669763763e0c46acfdefd8a2306de5ca8", 1390570126, 0x1901f52c },
    { 302400, "0000000000000000472132c4daaf358acaf461ff1c3e96577a74e5ebf91bb170", 1400928750, 0x18692842 },
    { 322560, "000000000000000002df2dd9d4fe0578392e519610e341dd09025469f101cfa1", 1411680080, 0x181fb893 },
    { 342720, "00000000000000000f9cfece8494800d3dcbf9583232825da640c8703bcd27e7", 1423496415, 0x1818bb87 },
    { 362880, "000000000000000014898b8e6538392702ffb9450f904c80ebf9d82b519a77d5", 1435475246, 0x1816418e },
    { 383040, "00000000000000000a974fa1a3f84055ad5ef0b2f96328bc96310ce83da801c9", 1447236692, 0x1810b289 },
    { 403200, "000000000000000000c4272a5c68b4f55e5af734e88ceab09abf73e9ac3b6d01", 1458292068, 0x1806a4c3 }
};

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
    btc_block_header header;
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
            btc_block_header_deserialize(&chainheader->header, &buf);
            btc_block_header_hash(&chainheader->header, (uint8_t *)&chainheader->hash);

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
            btc_block_header_deserialize(&chainheader->header, buf);

            /* skip tx count */
            deser_skip(buf, 1);

            /* calculate block hash */
            btc_block_header_hash(&chainheader->header, (uint8_t *)&chainheader->hash);

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
                btc_block_header_serialize(header_ser,&headerschaintip->header);
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

    int err = evutil_getaddrinfo((seed ? seed : "seed.bitcoin.jonasschnelli.ch"), def_port, &hints, &aiRes);
    if (err)
        return;

    aiTrav = aiRes;
    while (aiTrav != NULL)
    {
        int maxlen = 256;
        char *ipaddr = calloc(1, maxlen);
        if (aiTrav->ai_family == AF_INET)
        {
            assert(aiTrav->ai_addrlen >= sizeof(struct sockaddr_in));
            inet_ntop(aiTrav->ai_family, &((struct sockaddr_in*)(aiTrav->ai_addr))->sin_addr, ipaddr, maxlen);
        }

        if (aiTrav->ai_family == AF_INET6)
        {
            assert(aiTrav->ai_addrlen >= sizeof(struct sockaddr_in6));
            inet_ntop(aiTrav->ai_family, &((struct sockaddr_in6*)(aiTrav->ai_addr))->sin6_addr, ipaddr, maxlen);
        }

        memcpy(ipaddr+strlen(ipaddr), ":", 1);
        memcpy(ipaddr+strlen(ipaddr), def_port, strlen(def_port));;
        vector_add(ips_out, ipaddr);

        aiTrav = aiTrav->ai_next;
    }
    evutil_freeaddrinfo(aiRes);
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
