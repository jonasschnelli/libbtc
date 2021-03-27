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

#include <btc/base58.h>
#include <btc/blockchain.h>
#include <btc/segwit_addr.h>
#include <btc/serialize.h>
#include <btc/wallet.h>
#include <btc/utils.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _MSC_VER
#  include <unistd.h>
#endif


#include <search.h>

#define COINBASE_MATURITY 100

uint8_t WALLET_DB_REC_TYPE_MASTERPUBKEY = 0;
uint8_t WALLET_DB_REC_TYPE_PUBKEYCACHE = 1;
uint8_t WALLET_DB_REC_TYPE_ADDR = 1;
uint8_t WALLET_DB_REC_TYPE_TX = 2;

static const unsigned char file_hdr_magic[4] = {0xA8, 0xF0, 0x11, 0xC5}; /* header magic */
static const unsigned char file_rec_magic[4] = {0xC8, 0xF2, 0x69, 0x1E}; /* record magic */
static const uint32_t current_version = 1;

static const char hdkey_key[] = "hdkey";
static const char hdmasterkey_key[] = "mstkey";
static const char tx_key[] = "tx";


/* ====================== */
/* compare btree callback */
/* ====================== */
int btc_wallet_addr_compare(const void *l, const void *r)
{
    const btc_wallet_addr *lm = l;
    const btc_wallet_addr *lr = r;

    uint8_t *pubkeyA = (uint8_t *)lm->pubkeyhash;
    uint8_t *pubkeyB = (uint8_t *)lr->pubkeyhash;

    /* byte per byte compare */
    /* TODO: switch to memcmp */
    for (unsigned int i = 0; i < sizeof(uint160); i++) {
        uint8_t iA = pubkeyA[i];
        uint8_t iB = pubkeyB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }

    return 0;
}

int btc_wtx_compare(const void *l, const void *r)
{
    const btc_wtx *lm = l;
    const btc_wtx *lr = r;

    uint8_t *hashA = (uint8_t *)lm->tx_hash_cache;
    uint8_t *hashB = (uint8_t *)lr->tx_hash_cache;

    /* byte per byte compare */
    for (unsigned int i = 0; i < sizeof(uint256); i++) {
        uint8_t iA = hashA[i];
        uint8_t iB = hashB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }
    return 0;
}

int btc_tx_outpoint_compare(const void *l, const void *r)
{
    const btc_tx_outpoint *lm = l;
    const btc_tx_outpoint *lr = r;

    uint8_t *hashA = (uint8_t *)lm->hash;
    uint8_t *hashB = (uint8_t *)lr->hash;

    /* byte per byte compare */
    for (unsigned int i = 0; i < sizeof(uint256); i++) {
        uint8_t iA = hashA[i];
        uint8_t iB = hashB[i];
        if (iA > iB)
            return -1;
        else if (iA < iB)
            return 1;
    }
    if (lm->n > lr->n) {
        return -1;
    }
    if (lm->n < lr->n) {
        return 1;
    }
    return 0;
}


/*
 ==========================================================
 WALLET TRANSACTION (WTX) FUNCTIONS
 ==========================================================
*/
btc_wtx* btc_wallet_wtx_new()
{
    btc_wtx* wtx;
    wtx = btc_calloc(1, sizeof(*wtx));
    wtx->height = 0;
    wtx->ignore = false;
    btc_hash_clear(wtx->blockhash);
    btc_hash_clear(wtx->tx_hash_cache);
    wtx->tx = btc_tx_new();

    return wtx;
}

btc_wtx* btc_wallet_wtx_copy(btc_wtx* wtx)
{
    btc_wtx* wtx_copy;
    wtx_copy = btc_wallet_wtx_new();
    btc_tx_copy(wtx_copy->tx, wtx->tx);

    return wtx_copy;
}

void btc_wallet_wtx_free(btc_wtx* wtx)
{
    btc_tx_free(wtx->tx);
    btc_free(wtx);
}

void btc_wallet_wtx_serialize(cstring* s, const btc_wtx* wtx)
{
    ser_u32(s, wtx->height);
    ser_u256(s, wtx->tx_hash_cache);
    btc_tx_serialize(s, wtx->tx, true);
}

btc_bool btc_wallet_wtx_deserialize(btc_wtx* wtx, struct const_buffer* buf)
{
    deser_u32(&wtx->height, buf);
    deser_u256(wtx->tx_hash_cache, buf);
    return btc_tx_deserialize(buf->p, buf->len, wtx->tx, NULL, true);
}

void btc_wallet_wtx_cachehash(btc_wtx* wtx) {
    btc_tx_hash(wtx->tx, wtx->tx_hash_cache);
}


/*
 ==========================================================
 WALLET ADDRESS (WALLET_ADDR) FUNCTIONS
 ==========================================================
*/

btc_wallet_addr* btc_wallet_addr_new()
{
    btc_wallet_addr* waddr;
    waddr = btc_calloc(1, sizeof(*waddr));
    memset(waddr->pubkeyhash, 1, sizeof(waddr->pubkeyhash));
    return waddr;
}
void btc_wallet_addr_free(btc_wallet_addr* waddr)
{
    btc_free(waddr);
}

void btc_wallet_addr_serialize(cstring* s, const btc_chainparams *params, const btc_wallet_addr* waddr)
{
    (void)(params);
    ser_bytes(s, waddr->pubkeyhash, sizeof(uint160));
    ser_bytes(s, (unsigned char *)&waddr->type, sizeof(uint8_t));
    ser_u32(s, waddr->childindex);
}

btc_bool btc_wallet_addr_deserialize(btc_wallet_addr* waddr, const btc_chainparams *params, struct const_buffer* buf) {
    (void)(params);
    if (!deser_bytes(&waddr->pubkeyhash, buf, sizeof(uint160))) return false;
    if (!deser_bytes((unsigned char *)&waddr->type, buf, sizeof(uint8_t))) return false;
    if (!deser_u32(&waddr->childindex, buf)) return false;
    return true;
}

/*
 ==========================================================
 WALLET OUTPUT (prev wtx + n) FUNCTIONS
 ==========================================================
 */

btc_output* btc_wallet_output_new()
{
    btc_output* output;
    output = btc_calloc(1, sizeof(*output));
    output->i = 0;
    output->wtx = btc_wallet_wtx_new();

    return output;
}

void btc_wallet_output_free(btc_output* output)
{
    btc_wallet_wtx_free(output->wtx);
    btc_free(output);
}

/*
 ==========================================================
 WALLET CORE FUNCTIONS
 ==========================================================
 */
btc_wallet* btc_wallet_new(const btc_chainparams *params)
{
    btc_wallet* wallet;
    wallet = btc_calloc(1, sizeof(*wallet));
    wallet->masterkey = NULL;
    wallet->chain = params;
    wallet->spends = vector_new(10, free);

    wallet->wtxes_rbtree = 0;
    wallet->vec_wtxes = vector_new(10, NULL);
    wallet->hdkeys_rbtree = 0;
    wallet->waddr_rbtree = 0;
    wallet->spends_rbtree = 0;
    wallet->waddr_vector = vector_new(10, NULL);
    return wallet;
}

void btc_wallet_free(btc_wallet* wallet)
{
    if (!wallet)
        return;

    if (wallet->dbfile) {
        fclose(wallet->dbfile);
        wallet->dbfile = NULL;
    }

    if (wallet->spends) {
        vector_free(wallet->spends, true);
        wallet->spends = NULL;
    }

    if (wallet->masterkey)
        btc_free(wallet->masterkey);

    btc_btree_tdestroy(wallet->wtxes_rbtree, btc_free);
    btc_btree_tdestroy(wallet->hdkeys_rbtree, btc_free);
    btc_btree_tdestroy(wallet->waddr_rbtree, btc_free);
    btc_btree_tdestroy(wallet->spends_rbtree, btc_free);

    if (wallet->waddr_vector) {
        vector_free(wallet->waddr_vector, false);
        wallet->waddr_vector = NULL;
    }

    if (wallet->vec_wtxes) {
        vector_free(wallet->vec_wtxes, false);
        wallet->vec_wtxes = NULL;
    }

    btc_free(wallet);
}


btc_bool btc_wallet_create(btc_wallet* wallet, const char* file_path, int *error)
{
    if (!wallet)
        return false;

    struct stat buffer;
    if (stat(file_path, &buffer) != 0) {
        *error = 1;
        return false;
    }
    wallet->dbfile = fopen(file_path, "a+b");

    // write file-header-magic
    if (fwrite(file_hdr_magic, 4, 1, wallet->dbfile ) != 1 ) return false;

    // write version
    uint32_t v = htole32(current_version);
    if (fwrite(&v, sizeof(v), 1, wallet->dbfile ) != 1) return false;

    // write genesis
    if (fwrite(wallet->chain->genesisblockhash, sizeof(uint256), 1, wallet->dbfile ) != 1) return false;

    btc_file_commit(wallet->dbfile);
    return true;
}


void btc_wallet_add_wtx_intern_move(btc_wallet *wallet, const btc_wtx *wtx) {
    //add to spends
    btc_wallet_add_to_spent(wallet, wtx);

    btc_wtx* checkwtx = tfind(wtx, &wallet->wtxes_rbtree, btc_wtx_compare);
    if (checkwtx) {
        // remove existing wtx
        checkwtx = *(btc_wtx **)checkwtx;
        for (unsigned int i = 0; i < wallet->vec_wtxes->len; i++) {
            btc_wtx *wtx_vec = vector_idx(wallet->vec_wtxes, i);
            if (wtx_vec == checkwtx) {
                vector_remove_idx(wallet->vec_wtxes, i);
            }
        }
        // we do not really delete transactions
        checkwtx->ignore = true;
        tdelete(checkwtx, &wallet->wtxes_rbtree, btc_wtx_compare);
        btc_wallet_wtx_free(checkwtx);
    }
    checkwtx = tsearch(wtx, &wallet->wtxes_rbtree, btc_wtx_compare);
    vector_add(wallet->vec_wtxes,(btc_wtx *) wtx);
}


btc_bool btc_wallet_load(btc_wallet* wallet, const char* file_path, int *error, btc_bool *created)
{
    (void)(error);
    if (!wallet)
        return false;

    struct stat buffer;
    *created = true;
    if (stat(file_path, &buffer) == 0)
        *created = false;

    wallet->dbfile = fopen(file_path, *created ? "a+b" : "r+b");

    if (*created) {
        if (!btc_wallet_create(wallet, file_path, error)) {
            return false;
        }
    }
    else {
        // check file-header-magic, version and genesis
        uint8_t buf[sizeof(file_hdr_magic)+sizeof(current_version)+sizeof(uint256)];
        if ( (uint32_t)buffer.st_size < (uint32_t)(sizeof(buf)) ||
             fread(buf, sizeof(buf), 1, wallet->dbfile ) != 1 ||
             memcmp(buf, file_hdr_magic, sizeof(file_hdr_magic))
            )
        {
            fprintf(stderr, "Wallet file: error reading database file\n");
            return false;
        }
        if (le32toh(*(buf+sizeof(file_hdr_magic))) > current_version) {
            fprintf(stderr, "Wallet file: unsupported file version\n");
            return false;
        }
        if (memcmp(buf+sizeof(file_hdr_magic)+sizeof(current_version), wallet->chain->genesisblockhash, sizeof(uint256)) != 0) {
            fprintf(stderr, "Wallet file: different network\n");
            return false;
        }
        // read

        while (!feof(wallet->dbfile))
        {
            int eof = feof(wallet->dbfile );
            uint8_t buf[sizeof(file_rec_magic)];
            if ( fread(buf, sizeof(buf), 1, wallet->dbfile ) != 1 ) {
                // no more record, break
                break;
            }
            if (memcmp(buf, file_rec_magic, sizeof(file_rec_magic))) {
                fprintf(stderr, "Wallet file: error reading record file (invalid magic). Wallet file is corrupt\n");
                return false;
            }
            uint32_t reclen = 0;
            if (!deser_varlen_from_file(&reclen, wallet->dbfile)) return false;

            uint8_t rectype;
            if (fread(&rectype, 1, 1, wallet->dbfile ) != 1) return false;

            if (rectype == WALLET_DB_REC_TYPE_MASTERPUBKEY) {
                uint32_t len;
                char strbuf[196];
                memset(strbuf, 0, sizeof(strbuf));
                char strbuf_check[196];
                memset(strbuf_check, 0, sizeof(strbuf_check));
                if (!deser_varlen_from_file(&len, wallet->dbfile)) return false;
                if (len > sizeof(strbuf)) { return false; }
                if (fread(strbuf, len, 1, wallet->dbfile ) != 1) return false;
                if (!deser_varlen_from_file(&len, wallet->dbfile)) return false;
                if (len > sizeof(strbuf_check)) { return false; }
                if (fread(strbuf_check, len, 1, wallet->dbfile ) != 1) return false;

                if (strcmp(strbuf, strbuf_check) != 0) {
                    fprintf(stderr, "Wallet file: xpub check failed, corrupt wallet detected.\n");
                    return false;
                }
                wallet->masterkey = btc_hdnode_new();
                printf("xpub: %s\n", strbuf);
                btc_hdnode_deserialize(strbuf, wallet->chain, wallet->masterkey );
            }
            else if (rectype == WALLET_DB_REC_TYPE_ADDR) {
                uint32_t len;

                btc_wallet_addr *waddr= btc_wallet_addr_new();
                size_t reclen = 20+1+4;
                unsigned char buf[reclen];
                struct const_buffer cbuf = {buf, reclen};
                if (fread(buf, reclen, 1, wallet->dbfile ) != 1) {
                    btc_wallet_addr_free(waddr);
                    return false;
                }

                btc_wallet_addr_deserialize(waddr, wallet->chain, &cbuf);
                // add the node to the binary tree
                btc_wallet_addr* checkaddr = tsearch(waddr, &wallet->waddr_rbtree, btc_wallet_addr_compare);
                vector_add(wallet->waddr_vector, waddr);
                wallet->next_childindex = waddr->childindex+1;
            }
            else if (rectype == WALLET_DB_REC_TYPE_TX) {
                unsigned char buf[reclen];
                struct const_buffer cbuf = {buf, reclen};
                if (fread(buf, reclen, 1, wallet->dbfile ) != 1) {
                    return false;
                }
                btc_wtx *wtx = btc_wallet_wtx_new();
                btc_wallet_wtx_deserialize(wtx, &cbuf);
                btc_wallet_add_wtx_intern_move(wallet, wtx); // hands memory management over to the binary tree
            }
            else {
                fseek(wallet->dbfile , reclen, SEEK_CUR);
            }
        }
    }

    return true;
}

btc_bool btc_wallet_flush(btc_wallet* wallet)
{
    btc_file_commit(wallet->dbfile);
    return true;
}


btc_bool wallet_write_record(btc_wallet *wallet, const cstring* record, uint8_t record_type) {
    // write record magic
    if (fwrite(file_rec_magic, 4, 1, wallet->dbfile ) != 1 ) return false;

    //write record len
    cstring *cstr_len = cstr_new_sz(4);
    ser_varlen(cstr_len, record->len);
    if (fwrite(cstr_len->str, cstr_len->len, 1, wallet->dbfile ) != 1 ) {
        cstr_free(cstr_len, true);
        return false;
    }
    cstr_free(cstr_len, true);

    // write record type & record payload
    if (fwrite(&record_type, 1, 1, wallet->dbfile) != 1 ||
        fwrite(record->str, record->len, 1, wallet->dbfile) != 1) {
        return false;
    }
    return true;
}


void btc_wallet_set_master_key_copy(btc_wallet* wallet, const btc_hdnode* master_xpub)
{
    if (!master_xpub)
        return;

    if (wallet->masterkey != NULL) {
        //changing the master key should not be done,...
        //anyways, we are going to accept that at this point
        //consuming application needs to take care about that
        btc_hdnode_free(wallet->masterkey);
        wallet->masterkey = NULL;
    }
    wallet->masterkey = btc_hdnode_copy(master_xpub);

    cstring* record = cstr_new_sz(256);
    char strbuf[196];
    btc_hdnode_serialize_public(wallet->masterkey, wallet->chain, strbuf, sizeof(strbuf));
    printf("xpub: %s\n", strbuf);
    ser_str(record, strbuf, sizeof(strbuf));
    ser_str(record, strbuf, sizeof(strbuf));

    wallet_write_record(wallet, record, WALLET_DB_REC_TYPE_MASTERPUBKEY);

    cstr_free(record, true);

    btc_file_commit(wallet->dbfile);
}


btc_wallet_addr* btc_wallet_next_addr(btc_wallet* wallet)
{
    if (!wallet || !wallet->masterkey)
        return NULL;

    //for now, only m/k is possible
    btc_wallet_addr *waddr = btc_wallet_addr_new();
    btc_hdnode *hdnode = btc_hdnode_copy(wallet->masterkey);
    btc_hdnode_public_ckd(hdnode, wallet->next_childindex);
    btc_hdnode_get_hash160(hdnode, waddr->pubkeyhash);
    waddr->childindex = wallet->next_childindex;

    //add it to the binary tree
    // tree manages memory
    btc_wallet_addr* checknode = tsearch(waddr, &wallet->waddr_rbtree, btc_wallet_addr_compare);
    vector_add(wallet->waddr_vector, waddr);

    //serialize and store node
    cstring* record = cstr_new_sz(256);
    btc_wallet_addr_serialize(record, wallet->chain, waddr);
    if (!wallet_write_record(wallet, record, WALLET_DB_REC_TYPE_ADDR)) {
        fprintf(stderr, "Writing wallet address failed\n");
    }
    cstr_free(record, true);
    btc_file_commit(wallet->dbfile);

    //increase the in-memory counter (cache)
    wallet->next_childindex++;

    return waddr;
}

void btc_wallet_get_addresses(btc_wallet* wallet, vector* addr_out)
{
    for (unsigned int i = 0; i < wallet->waddr_vector->len; i++) {
        btc_wallet_addr *waddr = vector_idx(wallet->waddr_vector, i);
        size_t addrsize = 98;
        char* addr = btc_calloc(1, addrsize);
        btc_p2wpkh_addr_from_hash160(waddr->pubkeyhash, wallet->chain, addr);
        vector_add(addr_out, addr);
    }
}

btc_wallet_addr* btc_wallet_find_waddr_byaddr(btc_wallet* wallet, const char* search_addr)
{
    if (!wallet || !search_addr)
        return NULL;


    uint8_t *hashdata = (uint8_t *)btc_malloc(strlen(search_addr));
    memset(hashdata, 0, sizeof(uint160));
    int outlen = btc_base58_decode_check(search_addr, hashdata, strlen(search_addr));

    if (outlen > 0 && hashdata[0] == wallet->chain->b58prefix_pubkey_address) {

    } else if (outlen > 0 && hashdata[0] == wallet->chain->b58prefix_script_address) {

    }
    else {
        // check for bech32
        int version = 0;
        unsigned char programm[40] = {0};
        size_t programmlen = 0;
        if(segwit_addr_decode(&version, programm, &programmlen, wallet->chain->bech32_hrp, search_addr) == 1) {
            if (programmlen == 20) {
                memcpy(hashdata+1, (const uint8_t *)programm, 20);
            }
        }
        else {
            btc_free(hashdata);
            return NULL;
        }
    }

    btc_wallet_addr* waddr_search;
    waddr_search = btc_calloc(1, sizeof(*waddr_search));
    memcpy(waddr_search->pubkeyhash, hashdata+1, sizeof(uint160));

    btc_wallet_addr *needle = tfind(waddr_search, &wallet->waddr_rbtree, btc_wallet_addr_compare); /* read */
    if (needle) {
        needle = *(btc_wallet_addr **)needle;
    }
    btc_free(waddr_search);

    btc_free(hashdata);
    return needle;
}

btc_bool btc_wallet_add_wtx_move(btc_wallet* wallet, btc_wtx* wtx)
{
    if (!wallet || !wtx)
        return false;

    btc_wallet_wtx_cachehash(wtx);

    cstring* record = cstr_new_sz(1024);
    btc_wallet_wtx_serialize(record, wtx);

    if (!wallet_write_record(wallet, record, WALLET_DB_REC_TYPE_TX)) {
        fprintf(stderr, "Writing wtx record failed\n");
    }
    cstr_free(record, true);

    //add it to the binary tree
    btc_wallet_add_wtx_intern_move(wallet, wtx); //hands memory management over to the binary tree
    return true;
}

btc_bool btc_wallet_have_key(btc_wallet* wallet, uint160 hash160)
{
    if (!wallet)
        return false;

    btc_wallet_addr waddr_search;
    memcpy(&waddr_search.pubkeyhash, hash160, sizeof(uint160));

    btc_wallet_addr *needle = tfind(&waddr_search, &wallet->waddr_rbtree, btc_wallet_addr_compare); /* read */
    if (needle) {
        needle = *(btc_wallet_addr **)needle;
    }

    return (needle != NULL);
}

int64_t btc_wallet_get_balance(btc_wallet* wallet)
{
    int64_t credit = 0;

    if (!wallet)
        return false;

    for (unsigned int i = 0; i < wallet->vec_wtxes->len; i++) {
        btc_wtx *wtx = vector_idx(wallet->vec_wtxes, i);
        credit += btc_wallet_wtx_get_available_credit(wallet, wtx);
    }

    return credit;
}

int64_t btc_wallet_wtx_get_credit(btc_wallet* wallet, btc_wtx* wtx)
{
    int64_t credit = 0;

    if (btc_tx_is_coinbase(wtx->tx) &&
        (wallet->bestblockheight < COINBASE_MATURITY || wtx->height > wallet->bestblockheight - COINBASE_MATURITY))
        return credit;

    unsigned int i = 0;
    for (i = 0; i < wtx->tx->vout->len; i++) {
        btc_tx_out* tx_out;
        tx_out = vector_idx(wtx->tx->vout, i);
        if (btc_wallet_txout_is_mine(wallet, tx_out)) {
            credit += tx_out->value;
        }
    }
    return credit;
}

int64_t btc_wallet_wtx_get_available_credit(btc_wallet* wallet, btc_wtx* wtx)
{
    int64_t credit = 0;
    if (!wallet) {
        return credit;
    }

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (btc_tx_is_coinbase(wtx->tx) &&
        (wallet->bestblockheight < COINBASE_MATURITY || wtx->height > wallet->bestblockheight - COINBASE_MATURITY)) {
        return credit;
    }

    for (unsigned int i = 0; i < wtx->tx->vout->len; i++)
    {
        if (!btc_wallet_is_spent(wallet, wtx->tx_hash_cache, i))
        {
            btc_tx_out* tx_out = vector_idx(wtx->tx->vout, i);
            if (btc_wallet_txout_is_mine(wallet, tx_out)) {
                credit += tx_out->value;
            }
        }
    }

    return credit;
}

btc_bool btc_wallet_txout_is_mine(btc_wallet* wallet, btc_tx_out* tx_out)
{
    if (!wallet || !tx_out) return false;

    btc_bool ismine = false;

    vector* vec = vector_new(16, free);
    enum btc_tx_out_type type = btc_script_classify(tx_out->script_pubkey, vec);

    //TODO: Multisig, etc.
    if (type == BTC_TX_PUBKEYHASH) {
        //TODO: find a better format for vector elements (not a pure pointer)
        uint8_t* hash160 = vector_idx(vec, 0);
        if (btc_wallet_have_key(wallet, hash160))
            ismine = true;
    }
    else if (type == BTC_TX_WITNESS_V0_PUBKEYHASH && vec->len == 1) {
        uint8_t *hash160 = vector_idx(vec, 0);
        if (btc_wallet_have_key(wallet, hash160))
            ismine = true;
    }

    vector_free(vec, true);
    return ismine;
}

btc_bool btc_wallet_is_mine(btc_wallet* wallet, const btc_tx *tx)
{
    if (!wallet || !tx) return false;
    if (tx->vout) {
        for (unsigned int i = 0; i < tx->vout->len; i++) {
            btc_tx_out* tx_out = vector_idx(tx->vout, i);
            if (tx_out && btc_wallet_txout_is_mine(wallet, tx_out)) {
                return true;
            }
        }
    }
    return false;
}

int64_t btc_wallet_get_debit_txi(btc_wallet *wallet, const btc_tx_in *txin) {
    if (!wallet || !txin) return 0;

    btc_wtx wtx;
    memcpy(wtx.tx_hash_cache, txin->prevout.hash, sizeof(wtx.tx_hash_cache));

    btc_wtx* prevwtx = tfind(&wtx, &wallet->wtxes_rbtree, btc_wtx_compare);
    if (prevwtx) {
        // remove existing wtx
        prevwtx = *(btc_wtx **)prevwtx;

        if (txin->prevout.n < prevwtx->tx->vout->len) {
            btc_tx_out *tx_out = vector_idx(prevwtx->tx->vout, txin->prevout.n);
            if (tx_out && btc_wallet_txout_is_mine(wallet, tx_out)) {
                return tx_out->value;
            }
            //if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                //return prev.tx->vout[txin.prevout.n].nValue;
        }
    }

    return 0;
}

int64_t btc_wallet_get_debit_tx(btc_wallet *wallet, const btc_tx *tx) {
    int64_t debit = 0;
    if (tx->vin) {
        for (unsigned int i = 0; i < tx->vin->len; i++) {
            btc_tx_in* tx_in= vector_idx(tx->vin, i);
            if (tx_in) {
                debit += btc_wallet_get_debit_txi(wallet, tx_in);
            }
        }
    }
    return debit;
}

btc_bool btc_wallet_is_from_me(btc_wallet *wallet, const btc_tx *tx)
{
    return (btc_wallet_get_debit_tx(wallet, tx) > 0);
}

void btc_wallet_add_to_spent(btc_wallet* wallet, const btc_wtx* wtx) {
    if (!wallet || !wtx)
        return;

    if (btc_tx_is_coinbase(wtx->tx))
        return;

    unsigned int i = 0;
    if (wtx->tx->vin) {
        for (i = 0; i < wtx->tx->vin->len; i++) {
            btc_tx_in* tx_in = vector_idx(wtx->tx->vin, i);

            // form outpoint
            btc_tx_outpoint* outpoint = btc_calloc(1, sizeof(btc_tx_outpoint));
            memcpy(outpoint, &tx_in->prevout, sizeof(btc_tx_outpoint));

            // add to binary tree
            // memory is managed there (will free on tdestroy
            tsearch(outpoint, &wallet->spends_rbtree, btc_tx_outpoint_compare);
        }
    }
}

btc_bool btc_wallet_is_spent(btc_wallet* wallet, uint256 hash, uint32_t n)
{
    if (!wallet)
        return false;

    btc_tx_outpoint outpoint;
    memcpy(&outpoint.hash, hash, sizeof(uint256));
    outpoint.n = n;
    btc_tx_outpoint* possible_found = tfind(&outpoint, &wallet->spends_rbtree, btc_tx_outpoint_compare);
    if (possible_found) {
        possible_found = *(btc_tx_outpoint **)possible_found;
    }

    return (possible_found != NULL);
}

btc_wtx * btc_wallet_get_wtx(btc_wallet* wallet, const uint256 hash) {
    btc_wtx find;
    find.tx = NULL;
    btc_hash_set(find.tx_hash_cache, hash);
    btc_wtx* check_wtx = tfind(&find, &wallet->wtxes_rbtree, btc_wtx_compare);
    if (check_wtx) {
        return *(btc_wtx **)check_wtx;
    }
    return NULL;
}

btc_bool btc_wallet_get_unspent(btc_wallet* wallet, vector* unspents)
{
    if (!wallet || !unspents) {
        return false;
    }
    for (unsigned int i = 0; i < wallet->vec_wtxes->len; i++) {
        btc_wtx *wtx = vector_idx(wallet->vec_wtxes, i);
        for (unsigned int i = 0; i < wtx->tx->vout->len; i++)
        {
            if (!btc_wallet_is_spent(wallet, wtx->tx_hash_cache, i))
            {
                btc_tx_out* tx_out = vector_idx(wtx->tx->vout, i);
                if (btc_wallet_txout_is_mine(wallet, tx_out)) {
                    btc_tx_outpoint *outpoint = btc_calloc(1, sizeof(btc_tx_outpoint));
                    btc_hash_set(outpoint->hash, wtx->tx_hash_cache);
                    outpoint->n = i;
                    vector_add(unspents, outpoint);
                }
            }
        }
    }
    return true;
}

void btc_wallet_check_transaction(void *ctx, btc_tx *tx, unsigned int pos, btc_blockindex *pindex) {
    (void)(pos);
    (void)(pindex);
    btc_wallet *wallet = (btc_wallet *)ctx;
    if (btc_wallet_is_mine(wallet, tx) || btc_wallet_is_from_me(wallet, tx)) {
        printf("\nFound relevant transaction!\n");
    }
}
