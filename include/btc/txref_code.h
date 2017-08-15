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

#ifndef _BTC_TXREF_CODE_H_
#define _BTC_TXREF_CODE_H_ 1

#include <stdint.h>


static const char TXREF_BECH32_HRP_MAINNET[] = "tx";
static const char TXREF_BECH32_HRP_TESTNET[] = "txtest";

#define TXREF_MAGIC_BTC_MAINNET 0x03
#define TXREF_MAGIC_BTC_TESTNET 0x06

/** Encodes a transaction reference
 *
 *  Out: *output      :  Pointer to a buffer of size strlen(hrp) + 21 + 1(0 byte) that
 *                       will be updated to contain the null-terminated Bech32 string.
 *  In:  hrp          :  Human readable part ("tx" for mainnet, "testtx" for testnet, etc.)
 *                    :  If NULL, mainnet's "tx" will be used
 *       magic        :  5bit magic that will be place in the inner Bech32 part.
 *                      (ONLY 5bit magic (0x0 to 0x7) are supported for now)
 *       block_height :  The block height to encode
 *       tx_pos       :  The tx position to encode
 *       non_standard :  If set to 1, the limits for height and txpos are 0x3FFFFFF (height)
 *                       and 0x3FFFF (pos) and, the output will be 2 chars longer
 *  Returns 1 if successful.
 */
int btc_txref_encode(
    char *output,
    const char *hrp,
    const char magic,
    int block_height,
    int tx_pos,
    int non_standard
);

/** Decodes a transaction reference
 *
 *  In:  txref_id      :  Pointer to tx-ref encoded null-terminated Bech32 string.
 *  Out: *hrp          :  Human readabble part, make sure the buffer you pass in is
                          at least the size of strlen(txref_id)
 *       *magic        :  5bit magic (as char) that will contain the used magic during encoding
 *                        (ONLY 5bit magic (0x0 to 0x7) are supported for now)
 *       *block_height :  Pointer to integer the will be updated with the decoded block height
 *       *tx_pos       :  Pointer to integer the will be updated with the decoded tx position
 *  Returns 1 if successful.
 */
int btc_txref_decode(
    const char *txref_id,
    char *hrp,
    char *magic,
    int *block_height,
    int *tx_pos
);

#endif // _BTC_TXREF_CODE_H_
