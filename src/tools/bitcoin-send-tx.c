/*

 The MIT License (MIT)

 Copyright (c) 2017 Jonas Schnelli

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
#include <btc/tool.h>
#include <btc/ecc.h>
#include <btc/protocol.h>
#include <btc/tx.h>
#include <btc/utils.h>

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

static struct option long_options[] =
{
    {"testnet", no_argument, NULL, 't'},
    {"regtest", no_argument, NULL, 'r'},
    {"ips", no_argument, NULL, 'i'},
    {NULL, 0, NULL, 0}
};

static void print_version() {
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

static void print_usage() {
    print_version();
    printf("Usage: bitcoin-send-tx (-i|-ips <ip,ip,...]>) (-t[--testnet]) (-r[--regtest]) <txhex>\n");
    printf("\nExamples: \n");
    printf("Send a TX to random peers on testnet:\n");
    printf("> bitcoin-send-tx --testnet <txhex>\n\n");
    printf("Send a TX to specific peers on mainnet:\n");
    printf("> bitcoin-send-tx -i 127.0.0.1:8333,192.168.0.1:8333 <txhex>\n\n");
}

static bool showError(const char *er)
{
    printf("Error: %s\n", er);
    return 1;
}

int main(int argc, char *argv[])
{
    int long_index =0;
    char opt = 0;
    char *data = 0;
    char *ips = 0;
    const btc_chainparams* chain = &btc_chainparams_main;

    if (argc <= 1 || strlen(argv[argc-1]) == 0 || argv[argc-1][0] == '-')
    {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
    }
    data = argv[argc-1];

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv,"i:tr", long_options, &long_index )) != -1) {
        switch (opt) {
            case 't' :
                chain = &btc_chainparams_test;
                break;
            case 'r' :
                chain = &btc_chainparams_regtest;
                break;
            case 'i' : ips = optarg;
                break;
            case 'v' :
                print_version();
                exit(EXIT_SUCCESS);
                break;
            default: print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (data == NULL || strlen(data) == 0 || strlen(data) > BTC_MAX_P2P_MSG_SIZE) {
        return showError("Transaction in invalid or to large.\n");
    }
    uint8_t *data_bin = malloc(strlen(data)/2+1);
    int outlen = 0;
    utils_hex_to_bin(data, data_bin, strlen(data), &outlen);

    btc_tx* tx = btc_tx_new();
    if (btc_tx_deserialize(data_bin, outlen, tx, NULL)) {
        broadcast_tx(chain, tx, ips);
    }
    else {
        showError("Transaction is invalid\n");
    }
    free(data_bin);
    btc_tx_free(tx);

    return 0;
}
