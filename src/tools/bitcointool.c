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

#include "libbtc-config.h"

#include <btc/chainparams.h>
#include <btc/ecc.h>
#include <btc/protocol.h>
#include <btc/serialize.h>
#include <btc/tool.h>
#include <btc/tx.h>
#include <btc/utils.h>

#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


static struct option long_options[] =
    {
        {"privkey", required_argument, NULL, 'p'},
        {"pubkey", required_argument, NULL, 'k'},
        {"keypath", required_argument, NULL, 'm'},
        {"command", required_argument, NULL, 'c'},
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"version", no_argument, NULL, 'v'},
        {"txhex", no_argument, NULL, 'x'},
        {"scripthex", no_argument, NULL, 's'},
        {"inputindex", no_argument, NULL, 'i'},
        {"sighashtype", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}};

static void print_version()
{
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

static void print_usage()
{
    print_version();
    printf("Usage: bitcointool (-m|-keypath <bip_keypath>) (-k|-pubkey <publickey>) (-p|-privkey <privatekey>) (-t[--testnet]) (-r[--regtest]) -c <command>\n");
    printf("Available commands: pubfrompriv (requires -p WIF), addrfrompub (requires -k HEX), genkey, hdgenmaster, hdprintkey (requires -p), hdderive (requires -m and -p) \n");
    printf("\nExamples: \n");
    printf("Generate a testnet privatekey in WIF/HEX format:\n");
    printf("> bitcointool -c genkey --testnet\n\n");
    printf("> bitcointool -c pubfrompriv -p KzLzeMteBxy8aPPDCeroWdkYPctafGapqBAmWQwdvCkgKniH9zw6\n\n");
}

static bool showError(const char* er)
{
    printf("Error: %s\n", er);
    btc_ecc_stop();
    return 1;
}

int main(int argc, char* argv[])
{
    int long_index = 0;
    int opt = 0;
    char* pkey      = 0;
    char* pubkey    = 0;
    char* cmd       = 0;
    char* keypath   = 0;
    char* txhex     = 0;
    char* scripthex = 0;
    int inputindex  = 0;
    int sighashtype = 1;
    const btc_chainparams* chain = &btc_chainparams_main;

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "h:i:s:x:p:k:m:c:trv", long_options, &long_index)) != -1) {
        switch (opt) {
        case 'p':
            pkey = optarg;
            if (strlen(pkey) < 50)
                return showError("Private key must be WIF encoded");
            break;
        case 'c':
            cmd = optarg;
            break;
        case 'm':
            keypath = optarg;
            break;
        case 'k':
            pubkey = optarg;
            break;
        case 't':
            chain = &btc_chainparams_test;
            break;
        case 'r':
            chain = &btc_chainparams_regtest;
            break;
        case 'v':
            print_version();
            exit(EXIT_SUCCESS);
            break;
        case 'x':
            txhex = optarg;
            break;
        case 's':
            scripthex = optarg;
            break;
        case 'i':
            inputindex = (int)strtol(optarg, (char**)NULL, 10);
            break;
        case 'h':
            sighashtype = (int)strtol(optarg, (char**)NULL, 10);
            break;
        default:
            print_usage();
            exit(EXIT_FAILURE);
        }
    }

    if (!cmd) {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* start ECC context */
    btc_ecc_start();

    const char *pkey_error = "Missing extended key (use -p)";

    if (strcmp(cmd, "pubfrompriv") == 0) {
        /* output compressed hex pubkey from hex privkey */

        size_t sizeout = 128;
        char pubkey_hex[sizeout];
        if (!pkey)
            return showError(pkey_error);
        if (!pubkey_from_privatekey(chain, pkey, pubkey_hex, &sizeout))
            return showError("Operation failed");

        /* clean memory of private key */
        memset(pkey, 0, strlen(pkey));

        /* give out hex pubkey */
        printf("pubkey: %s\n", pubkey_hex);

        /* give out p2pkh address */
        char address[sizeout];
        address_from_pubkey(chain, pubkey_hex, address);
        printf("p2pkh address: %s\n", address);

        /* clean memory */
        memset(pubkey_hex, 0, strlen(pubkey_hex));
        memset(address, 0, strlen(address));
    } else if (strcmp(cmd, "addrfrompub") == 0 || strcmp(cmd, "p2pkhaddrfrompub") == 0) {
        /* get p2pkh address from pubkey */

        size_t sizeout = 128;
        char address[sizeout];
        if (!pubkey)
            return showError("Missing public key (use -k)");
        if (!address_from_pubkey(chain, pubkey, address))
            return showError("Operation failed, invalid pubkey");
        printf("p2pkh address: %s\n", address);
        memset(pubkey, 0, strlen(pubkey));
        memset(address, 0, strlen(address));
    } else if (strcmp(cmd, "genkey") == 0) {
        size_t sizeout = 128;
        char newprivkey_wif[sizeout];
        char newprivkey_hex[sizeout];

        /* generate a new private key */
        gen_privatekey(chain, newprivkey_wif, sizeout, newprivkey_hex);
        printf("privatekey WIF: %s\n", newprivkey_wif);
        printf("privatekey HEX: %s\n", newprivkey_hex);
        memset(newprivkey_wif, 0, strlen(newprivkey_wif));
        memset(newprivkey_hex, 0, strlen(newprivkey_hex));
    } else if (strcmp(cmd, "hdgenmaster") == 0) {
        size_t sizeout = 128;
        char masterkey[sizeout];

        /* generate a new hd master key */
        hd_gen_master(chain, masterkey, sizeout);
        printf("masterkey: %s\n", masterkey);
        memset(masterkey, 0, strlen(masterkey));
    } else if (strcmp(cmd, "hdprintkey") == 0) {
        if (!pkey)
            return showError(pkey_error);
        if (!hd_print_node(chain, pkey))
            return showError("Failed. Probably invalid extended key.\n");
    } else if (strcmp(cmd, "hdderive") == 0) {
        if (!pkey)
            return showError(pkey_error);
        if (!keypath)
            return showError("Missing keypath (use -m)");
        size_t sizeout = 128;
        char newextkey[sizeout];
        if (!hd_derive(chain, pkey, keypath, newextkey, sizeout))
            return showError("Deriving child key failed\n");
        else
            hd_print_node(chain, newextkey);
    } else if (strcmp(cmd, "sighash") == 0) {
        if(!txhex || !scripthex) {
            return showError("Missing tx-hex or script-hex (use -x, -s)\n");
        }

        if (strlen(txhex) > 1024*100) { //don't accept tx larger then 100kb
            return showError("tx too large (max 100kb)\n");
        }

        //deserialize transaction
        btc_tx* tx = btc_tx_new();
        uint8_t* data_bin = btc_malloc(strlen(txhex) / 2 + 1);
        int outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);

        if (!btc_tx_deserialize(data_bin, outlen, tx, NULL, true)) {
            return showError("Invalid tx hex");
        }

        if ((size_t)inputindex >= tx->vin->len) {
            return showError("Inputindex out of range");
        }

        btc_tx_in *tx_in = vector_idx(tx->vin, inputindex);

        uint8_t script_data[strlen(scripthex) / 2 + 1];
        utils_hex_to_bin(scripthex, script_data, strlen(scripthex), &outlen);
        cstring* script = cstr_new_buf(script_data, outlen);

        uint256 sighash;
        memset(sighash, 0, sizeof(sighash));
        btc_tx_sighash(tx, script, inputindex, sighashtype, 0, SIGVERSION_BASE, sighash);

        char *hex = utils_uint8_to_hex(sighash, 32);
        utils_reverse_hex(hex, 64);

        enum btc_tx_out_type type = btc_script_classify(script, NULL);
        printf("script: %s\n", scripthex);
        printf("script-type: %s\n", btc_tx_out_type_to_str(type));
        printf("inputindex: %d\n", inputindex);
        printf("sighashtype: %d\n", sighashtype);
        printf("hash: %s\n", hex);

        // sign
        btc_bool sign = false;
        btc_key key;
        btc_privkey_init(&key);
        if (btc_privkey_decode_wif(pkey, chain, &key)) {
            sign = true;
        }
        else {
            if (strlen(pkey) > 50) {
                return showError("Invalid wif privkey\n");
            }
        }
        if (sign) {
            uint8_t sig[100];
            size_t siglen = 0;
            btc_key_sign_hash_compact(&key, sighash, sig, &siglen);
            char sigcompacthex[64*2+1];
            memset(sigcompacthex, 0, sizeof(sigcompacthex));
            assert(siglen == 64);
            utils_bin_to_hex((unsigned char *)sig, siglen, sigcompacthex);

            unsigned char sigder_plus_hashtype[74+1];
            size_t sigderlen = 75;
            btc_ecc_compact_to_der_normalized(sig, sigder_plus_hashtype, &sigderlen);
            assert(sigderlen <= 74 && sigderlen > 70);
            sigder_plus_hashtype[sigderlen] = sighashtype;
            sigderlen+=1; //+hashtype

            char sigderhex[74*2+2+1]; //74 der, 2 hashtype, 1 nullbyte
            memset(sigderhex, 0, sizeof(sigderhex));
            utils_bin_to_hex((unsigned char *)sigder_plus_hashtype, sigderlen, sigderhex);

            printf("\nSignature created:\n");
            printf("signature compact: %s\n", sigcompacthex);
            printf("signature DER (+hashtype): %s\n", sigderhex);

            ser_varlen(tx_in->script_sig, sigderlen);
            ser_bytes(tx_in->script_sig, sigder_plus_hashtype, sigderlen);

            btc_pubkey pubkey;
            btc_pubkey_init(&pubkey);
            btc_pubkey_from_key(&key, &pubkey);

            ser_varlen(tx_in->script_sig, pubkey.compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);
            ser_bytes(tx_in->script_sig, pubkey.pubkey, pubkey.compressed ? BTC_ECKEY_COMPRESSED_LENGTH : BTC_ECKEY_UNCOMPRESSED_LENGTH);

            cstring* signed_tx = cstr_new_sz(1024);
            btc_tx_serialize(signed_tx, tx, true);

            char signed_tx_hex[signed_tx->len*2+1];
            utils_bin_to_hex((unsigned char *)signed_tx->str, signed_tx->len, signed_tx_hex);
            printf("signed TX: %s\n", signed_tx_hex);
        }
    }
    else if (strcmp(cmd, "comp2der") == 0) {
        if(!scripthex || strlen(scripthex) != 128) {
            return showError("Missing signature or invalid length (use hex, 128 chars == 64 bytes)\n");
        }

        int outlen = 0;
        uint8_t sig_comp[strlen(scripthex) / 2 + 1];
        //utils_reverse_hex(scripthex, strlen(scripthex));
        printf("%s\n", scripthex);
        utils_hex_to_bin(scripthex, sig_comp, strlen(scripthex), &outlen);

        unsigned char sigder[74];
        size_t sigderlen = 74;

        btc_ecc_compact_to_der_normalized(sig_comp, sigder, &sigderlen);
        char hexbuf[sigderlen*2 + 1];
        utils_bin_to_hex(sigder, sigderlen, hexbuf);
        printf("DER: %s\n", hexbuf);
    }
    else if (strcmp(cmd, "applysig") == 0) {
        if(!txhex || !scripthex) {
            return showError("Missing tx-hex or sig-hex (use -x, -s)\n");
        }
        if (strlen(txhex) > 100000) {
            return showError("tx too large\n");
        }
        btc_tx* tx = btc_tx_new();
        uint8_t* data_bin = btc_malloc(strlen(txhex) / 2 + 1);
        int outlen = 0;
        utils_hex_to_bin(txhex, data_bin, strlen(txhex), &outlen);

        if (!btc_tx_deserialize(data_bin, outlen, tx, NULL, true)) {
            return showError("Invalid tx hex\n");
        }

        btc_tx_in *txin = vector_idx(tx->vin, 0);
        printf("%u\n", txin->sequence);
        printf("%zu\n", txin->script_sig->len);

        outlen = 0;
        uint8_t script_sig[strlen(scripthex)];
        utils_hex_to_bin(scripthex, script_sig, strlen(scripthex), &outlen);

        cstr_append_buf(txin->script_sig, script_sig, outlen);

        cstring* sertx = cstr_new_sz(strlen(txhex) + 74+65);
        btc_tx_serialize(sertx, tx, true);
        char hexbuf[sertx->len * 2 + 1];
        utils_bin_to_hex((unsigned char*)sertx->str, sertx->len, hexbuf);

        printf("New TX Hex: %s\n", hexbuf);
    }
    else if (strcmp(cmd, "reverse") == 0) {
        if(!txhex) {
            return showError("Missing input (use -x)\n");
        }
        if (strlen(txhex) > 100000) {
            return showError("tx too large\n");
        }
        utils_reverse_hex(txhex, strlen(txhex));
        printf("reverse: %s\n", txhex);
    }

    btc_ecc_stop();

    return 0;
}
