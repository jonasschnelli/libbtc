/**********************************************************************
 * Copyright (c) 2015 Jonas Schnelli                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cstr.h"
#include "flags.h"
#include "utils.h"
#include "tx.h"

void test_tx()
{
    const char tx_hex[] = "01000000023d6cf972d4dff9c519eff407ea800361dd0a121de1da8b6f4138a2f25de864b4000000008a4730440220ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e022049cffa1cdc102a0b56e0e04913606c70af702a1149dc3b305ab9439288fee090014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd3227327694c4fa4c1c439affffffff21ebc9ba20594737864352e95b727f1a565756f9d365083eb1a8596ec98c97b7010000008a4730440220503ff10e9f1e0de731407a4a245531c9ff17676eda461f8ceeb8c06049fa2c810220c008ac34694510298fa60b3f000df01caa244f165b727d4896eb84f81e46bcc4014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd3227327694c4fa4c1c439affffffff01f0da5200000000001976a914857ccd42dded6df32949d4646dfa10a92458cfaa88ac00000000";

    uint8_t tx_data[sizeof(tx_hex)/2+1];
    int outlen;
    utils_hex_to_bin(tx_hex, tx_data, strlen(tx_hex), &outlen);

    lbc_tx *tx = lbc_tx_new();
    lbc_tx_parse(tx_data, strlen(tx_hex), tx);


    cstring *str = cstr_new_sz(200);
    lbc_tx_serialize(str, tx);

    char hexbuf[sizeof(tx_hex)+1];
    int outlen2;
    utils_bin_to_hex((unsigned char *)str->str, str->len, hexbuf);
    cstr_free(str, true);
    assert(memcmp(tx_hex, hexbuf, sizeof(tx_hex)) == 0);
    lbc_tx_free(tx);
}