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
#include <btc/ecc.h>
#include <btc/net.h>
#include <btc/netspv.h>
#include <btc/protocol.h>
#include <btc/serialize.h>
#include <btc/tool.h>
#include <btc/tx.h>
#include <btc/utils.h>

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct option long_options[] =
    {
        {"testnet", no_argument, NULL, 't'},
        {"regtest", no_argument, NULL, 'r'},
        {"ips", no_argument, NULL, 'i'},
        {"debug", no_argument, NULL, 'd'},
        {"maxnodes", no_argument, NULL, 'm'},
        {"dbfile", no_argument, NULL, 'f'},
        {NULL, 0, NULL, 0}};

static void print_version()
{
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

static void print_usage()
{
    print_version();
    printf("Usage: bitcoin-spv (-i|-ips <ip,ip,...]>) (-m[--maxpeers] <int>) (-t[--testnet]) (-r[--regtest]) (-d[--debug]) (-s[--timeout] <secs>) <txhex>\n");
    printf("\nExamples: \n");
    printf("Send a TX to random peers on testnet:\n");
    printf("> bitcoin-send-tx --testnet <txhex>\n\n");
    printf("Send a TX to specific peers on mainnet:\n");
    printf("> bitcoin-send-tx -i 127.0.0.1:8333,192.168.0.1:8333 <txhex>\n\n");
}

static bool showError(const char* er)
{
    printf("Error: %s\n", er);
    return 1;
}

btc_bool spv_header_message_processed(struct btc_spv_client_ *client, btc_node *node, btc_blockindex *newtip) {
    UNUSED(client);
    UNUSED(node);
    if (newtip) {
        printf("New headers tip height %d\n", newtip->height);
    }
    return true;
}

int main(int argc, char* argv[])
{
    int ret = 0;
    int long_index = 0;
    int opt = 0;
    char* data = 0;
    char* ips = 0;
    btc_bool debug = false;
    int timeout = 15;
    int maxnodes = 10;
    char* dbfile = 0;
    const btc_chainparams* chain = &btc_chainparams_main;

    if (argc <= 1 || strlen(argv[argc - 1]) == 0 || argv[argc - 1][0] == '-') {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
    }
    data = argv[argc - 1];

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "i:trds:m:f:", long_options, &long_index)) != -1) {
        switch (opt) {
        case 't':
            chain = &btc_chainparams_test;
            break;
        case 'r':
            chain = &btc_chainparams_regtest;
            break;
        case 'd':
            debug = true;
            break;
        case 's':
            timeout = (int)strtol(optarg, (char**)NULL, 10);
            break;
        case 'i':
            ips = optarg;
            break;
        case 'm':
            maxnodes = (int)strtol(optarg, (char**)NULL, 10);
            break;
        case 'f':
            dbfile = optarg;
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

    if (strcmp(data, "scan") == 0) {
        btc_spv_client* client = btc_spv_client_new(chain, debug, (dbfile && (dbfile[0] == '0' || (strlen(dbfile) > 1 && dbfile[0] == 'n' && dbfile[0] == 'o'))) ? true : false);
        client->header_message_processed = spv_header_message_processed;
        btc_spv_client_load(client, (dbfile ? dbfile : "headers.db"));

        printf("Discover peers...");
        btc_spv_client_discover_peers(client, ips);
        printf("done\n");
        printf("Start interacting with the p2p network...\n");
        btc_spv_client_runloop(client);
        btc_spv_client_free(client);
    }
    else {
        printf("Invalid command (use -?)\n");
        ret = EXIT_FAILURE;
    }
    return ret;
}
