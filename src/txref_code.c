/* Copyright (c) 2017 Jonas Schnelli
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <btc/segwit_addr.h>
#include <btc/txref_code.h>

static const unsigned int TXREF_LEN_WITHOUT_HRP = 15;

int btc_txref_encode(
    char *output,
    const char *hrp,
    const char magic,
    int block_height,
    int tx_pos,
    int non_standard
) {
    int res;
    /* Bech32 requires a array of 5bit chunks */
    uint8_t short_id[10] = {0};
    size_t olen;

    /* ensure we stay in boundaries */
    if (
          (non_standard == 0 && (block_height > 0x1FFFFF || tx_pos > 0x1FFF || magic > 0x1F))
          ||
          (non_standard == 1 && (block_height > 0x3FFFFFF || tx_pos > 0x3FFFF || magic > 0x1F))
       ) {
        return -1;
    }

    /* set the magic */
    short_id[0] = magic;

    /* make sure the version bit is 0 */
    short_id[1] &= ~(1 << 0);

    short_id[1] |= ((block_height & 0xF) << 1);
    short_id[2] |= ((block_height & 0x1F0) >> 4);
    short_id[3] |= ((block_height & 0x3E00) >> 9);
    short_id[4] |= ((block_height & 0x7C000) >> 14);
    if (non_standard == 0) {
      short_id[5] |= ((block_height & 0x180000) >> 19);
      short_id[5] |= ((tx_pos & 0x7) << 2);
      short_id[6] |= ((tx_pos & 0xF8) >> 3);
      short_id[7] |= ((tx_pos & 0x1F00) >> 8);
    }
    else {
      // use extended blockheight (up to 0x3FFFFFF)
      // use extended txpos (up to 0x3FFFF)
      short_id[5] |= ((block_height & 0xF80000) >> 19);
      short_id[6] |= ((block_height & 0x3000000) >> 24);

      short_id[6] |= ((tx_pos & 0x7) << 2);
      short_id[7] |= ((tx_pos & 0xF8) >> 3);
      short_id[8] |= ((tx_pos & 0x1F00) >> 8);
      short_id[9] |= ((tx_pos & 0x3E000) >> 13);
    }

    /* Bech32 encode the 8x5bit packages */
    const char *hrptouse = (hrp != NULL ? hrp : TXREF_BECH32_HRP_MAINNET);
    int hrplen = strlen(hrptouse);
    res = bech32_encode(output, hrptouse, short_id, (non_standard == 1 ? 10 : 8));
    /* add the dashes */
    olen = strlen(output);
    if (non_standard == 0) {
      memcpy(output+olen+2, output+olen-2, 2); //including 0 byte
      output[olen+4] = 0;
      memcpy(output+olen-3, output+olen-6, 4);
      memcpy(output+olen-8, output+olen-10, 4);
      memcpy(output+olen-13, output+olen-14, 4);
      output[1+hrplen] = '-'; output[6+hrplen] = '-'; output[11+hrplen] = '-'; output[16+hrplen] = '-';
    }
    else {
      // use 16 char encoding (test networks)
      memcpy(output+olen, output+olen-4, 4); //including 0 byte
      output[olen+4] = 0;
      memcpy(output+olen-5, output+olen-8, 4);
      memcpy(output+olen-10, output+olen-12, 4);
      memcpy(output+olen-15, output+olen-16, 4);
      output[1+hrplen] = '-'; output[6+hrplen] = '-'; output[11+hrplen] = '-'; output[16+hrplen] = '-';
    }
    return res;
}

int btc_txref_decode(
    const char *txref_id,
    char *hrp,
    char *magic,
    int *block_height,
    int *tx_pos
) {
    unsigned int i;
    size_t outlen = 0;
    uint8_t buf[strlen(txref_id)];
    int res;

    /* max TXREF_LEN_WITHOUT_HRP (+4 dashes) chars are allowed for now */
    if (strlen(txref_id) < TXREF_LEN_WITHOUT_HRP+4) {
        return -1;
    }
    char txref_id_no_d[strlen(txref_id)]; //+1 for the null byte term.
    memset(txref_id_no_d, 0, sizeof(txref_id_no_d));

    for(i = 0; i < strlen(txref_id); i++) {
        if (txref_id[i]!='-') {
            txref_id_no_d[strlen(txref_id_no_d)] = txref_id[i];
        }
    }

    /* Bech32 decode */
    res = bech32_decode(hrp, buf, &outlen, txref_id_no_d);
    /* ensure we have 8x5bit or 10x5bit (test-networks) */
    if (outlen != 8 && outlen != 10) {
        return -1;
    }
    if (!res) {
        return res;
    }

    /* set the magic */
    *magic = buf[0];

    /* set the block height */
    *block_height = (buf[1] >> 1);
    *block_height |= (buf[2] << 4);
    *block_height |= (buf[3] << 9);
    *block_height |= (buf[4] << 14);
    if (outlen == 8) {
      *block_height |= ((buf[5] & 0x03) << 19);

      /* set the tx position */
      *tx_pos = ((buf[5] & 0x1C) >> 2);
      *tx_pos |= (buf[6] << 3);
      *tx_pos |= (buf[7] << 8);
    }
    else {
      /* use extended blockheight / txpos (test networks) */
      *block_height |= (buf[5] << 19);
      *block_height |= ((buf[6] & 0x03) << 24);

      /* set the tx position */
      *tx_pos = ((buf[6] & 0x1C) >> 2);
      *tx_pos |= (buf[7] << 3);
      *tx_pos |= (buf[8] << 8);
      *tx_pos |= (buf[9] << 13);
    }

    return 1;
}
