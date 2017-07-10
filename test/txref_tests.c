/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <btc/txref_code.h>

#include "utest.h"
#include <btc/utils.h>

struct test_vector {
    const char magic;
    const char *hrp;
    const char* txref_encoded;
    int blockheight;
    int pos;
    int enc_fail; //0 == must not fail, 1 == can fail, 2 == can fail and continue with next test, 3 == skip
    int dec_fail;
    int non_std;
};

static struct test_vector test_vectors[] = {
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rjk0-u5ng-4jsf-mc",
        466793,
        2205,
        0,0,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rjk0-u5n1-2jsi-mc", /* error correct test >2tsi< instead of >4jsf<*/
        466793,
        2205,
        1,0,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rqqq-qqqq-qmhu-qk",
        0,
        0,
        0,0,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rzqq-qqqq-uvlj-ez",
        1,
        0,
        0,0,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rjk0-u5ng-4jsf-mc", /* complete invalid */
        0,
        0,
        1,1,0 /* enc & dec must fail */
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-r7ll-lrar-a27h-kt",
        2097151, /* last valid block height with current enc/dec version is 0x1FFFFF*/
        1000,
        0,0,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "", /* encoding must fail, no txref to chain against */
        2097152, /* invalid height */
        1000,
        2,1,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-r7ll-llll-khym-tq",
        2097151, /* last valid block height with current enc/dec version is 0x1FFFFF*/
        8191, /* last valid tx pos is 0x1FFF */
        0,0,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "", /* encoding must fail, no txref to chain against */
        2097151, /* last valid block height with current enc/dec version is 0x1FFFFF*/
        8192, /* invalid tx pos */
        2,1,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-r7ll-lrqq-vq5e-gg",
        2097151, /* last valid block height with current enc/dec version is 0x1FFFFF*/
        0,
        0,0,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rqqq-qull-6v87-r7",
        0,
        8191, /* last valid tx pos is 0x1FFF */
        0,0,0
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rjk0-u5ng-gghq-fkg7", /* valid Bech32, but 10x5bit packages instead of 8 */
        0,
        0,
        3,2,0 /* ignore encoding */
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rjk0-u5qd-s43z", /* valid Bech32, but 6x5bit packages instead of 8 */
        0,
        0,
        3,2,0 /* ignore encoding */
    },
    {
        0xB,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-t7ll-llll-gey7-ez",
        2097151,
        8191,
        0,0,0 /* ignore encoding */
    },
    {
        TXREF_MAGIC_BTC_MAINNET,
        TXREF_BECH32_HRP_MAINNET,
        "tx1-rk63-uvxf-9pqc-sy",
        467883,
        2355,
        0,0,0 /* ignore encoding */
    },
    {
        TXREF_MAGIC_BTC_TESTNET,
        TXREF_BECH32_HRP_TESTNET,
        "txtest1-xk63-uqvx-fqx8-xqr8",
        467883,
        2355,
        0,0,1 /* ignore encoding */
    },
    {
        TXREF_MAGIC_BTC_TESTNET,
        TXREF_BECH32_HRP_TESTNET,
        "txtest1-xqqq-qqqq-qqkn-3gh9",
        0,
        0,
        0,0,1 /* ignore encoding */
    },
    {
        TXREF_MAGIC_BTC_TESTNET,
        TXREF_BECH32_HRP_TESTNET,
        "txtest1-x7ll-llll-llj9-t9dk",
        0x3FFFFFF,
        0x3FFFF,
        0,0,1 /* ignore encoding */
    },
};

void test_txref()
{
    int fail = 0;
    int fail_in = 0;
    size_t i;
    char magic;
    int bh_check;
    int pos_check;
    int res;
    char encoded_txref[32] = {};

    char hrpbuf[1024];
    for (i = 0; i < sizeof(test_vectors) / sizeof(test_vectors[0]); ++i) {
        fail_in = 0;
        memset(encoded_txref, 0, sizeof(encoded_txref));
        memset(hrpbuf, 0, sizeof(hrpbuf));
        if (test_vectors[i].enc_fail != 3) {
            res = btc_txref_encode(encoded_txref, test_vectors[i].hrp, test_vectors[i].magic, test_vectors[i].blockheight, test_vectors[i].pos, test_vectors[i].non_std);
            if (strcmp(test_vectors[i].txref_encoded, encoded_txref) != 0 && !test_vectors[i].enc_fail) {
                fail++;
                fail_in = 1;
            }
            if (test_vectors[i].enc_fail == 2) {
                if (fail_in) {
                  printf("Failed encoding in %s (%d)\n", encoded_txref, (int)i);
                }
                continue;
            }
            res = btc_txref_decode(encoded_txref, hrpbuf, &magic, &bh_check, &pos_check);
        }
        else {
            res = btc_txref_decode(test_vectors[i].txref_encoded, hrpbuf, &magic, &bh_check, &pos_check);
        }
        if (res!=1 && !test_vectors[i].dec_fail) {
            fail++;
        }
        if (test_vectors[i].dec_fail == 2) {
            if (fail_in) {
              printf("Failed decoding in %s (%d)\n", encoded_txref, (int)i);
            }
            continue;
        }
        /* make sure the human readable part matches */
        if (strncmp(hrpbuf, test_vectors[i].hrp, strlen(test_vectors[i].hrp)) != 0) {
            fail++;
        }
        if (test_vectors[i].pos != pos_check) {
            fail++;
        }
        if (test_vectors[i].blockheight != bh_check) {
            fail++;
        }
        if (magic != test_vectors[i].magic) {
            fail++;
        }

        if (fail_in) {
          printf("Failed decoding in %s (%d)\n", encoded_txref, (int)i);
        }
    }

    u_assert_int_eq(fail, 0);
}
