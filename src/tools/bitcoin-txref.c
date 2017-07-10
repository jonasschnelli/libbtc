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
#include <btc/txref_code.h>

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
        {"debug", no_argument, NULL, 'd'},
        {NULL, 0, NULL, 0}};

static void print_version()
{
    printf("Version: %s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
}

static void print_usage()
{
    print_version();
    printf("Usage: bitcoin-txref (-t[--testnet]) (-r[--regtest]) (-d[--debug]) <block-height>|<encoded txref> (<tx-position>)\n");
    printf("\nExamples: \n");
    printf("Encode tx as pos 1 in block 100:\n");
    printf("> bitcoin-txref 100 1\n\n");
    printf("Encode tx as pos 1 in block 100 (testnet):\n");
    printf("> bitcoin-txref -t 100 1\n\n");
    printf("Decode txref-code:\n");
    printf("> bitcoin-txref tx1-rgxq-qyqq-wutf-dp\n\n");
}

static bool showError(const char* er)
{
    printf("Error: %s\n", er);
    return 1;
}


int main(int argc, char* argv[])
{
    int ret = 0;
    int long_index = 0;
    int opt = 0;
    char* blockheight = 0;
    char* txpos = 0;
    btc_bool debug = false;
    const btc_chainparams* chain = &btc_chainparams_main;

    if (argc <= 1 || strlen(argv[argc - 1]) == 0 ||  argv[argc - 1][0] == '-') {
        /* exit if no command was provided */
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* get arguments */
    while ((opt = getopt_long_only(argc, argv, "trd", long_options, &long_index)) != -1) {
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
        default:
            print_usage();
            exit(EXIT_FAILURE);
        }
    }

    if (argc > 2 && strlen(argv[argc - 1]) > 0 && argv[argc - 1][0] != '-' && strlen(argv[argc - 2]) > 0 && argv[argc - 2][0] != '-' ) {
        int height = (int)strtol(argv[argc - 2], (char**)NULL, 10);
        int pos = (int)strtol(argv[argc - 1], (char**)NULL, 10);

        char encoded_txref[22+strlen(chain->txref_code_hrp)];
        memset(encoded_txref, 0, sizeof(encoded_txref));

        if (height == 0 && pos == 0) {
            fprintf(stderr, "Invalid height / pos\n");
        }
        else if (btc_txref_encode(encoded_txref, chain->txref_code_hrp, chain->txref_code_magic, height, pos, chain->txref_code_testnet)) {
            printf("Height: %d\n", height);
            printf("Position: %d\n", pos);
            printf("Network: %s\n", chain->chainname);
            printf("%s\n", encoded_txref);
        }
        else {
            fprintf(stderr, "Encoding transaction reference failed!\n");
        }
    }
    else {
        char magic;
        int height;
        int pos;
        char hrp[strlen(argv[argc - 1])];
        if (btc_txref_decode(argv[argc - 1], hrp, &magic, &height, &pos)) {
            printf("Height: %d\n", height);
            printf("Position: %d\n", pos);
            printf("Magic: %d\n", magic);
            if ((int)chain->txref_code_magic != (int)magic) {
                printf("Notice: different network\n");
            }
        }
        else {
            fprintf(stderr, "Error decoding transaction reference.\n");
        }
    }





    return ret;
}
