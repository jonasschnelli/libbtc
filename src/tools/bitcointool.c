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
    char* pkey = 0;
    char* pubkey = 0;
    char* cmd = 0;
    char* keypath = 0;
    const btc_chainparams* chain = &btc_chainparams_main;

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "p:k:m:c:trv", long_options, &long_index)) != -1) {
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
    }

    btc_ecc_stop();

    return 0;
}
