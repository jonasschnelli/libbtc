
#ifndef LIBBTC_BLOCK_H
#define LIBBTC_BLOCK_H


#include "btc.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include "hash.h"
#include "cstr.h"

typedef struct btc_block_header_ {
    int32_t version;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
} btc_block_header;

LIBBTC_API btc_block_header* btc_block_header_new();
LIBBTC_API void btc_block_header_free(btc_block_header* header);
LIBBTC_API int btc_block_header_deserialize(const unsigned char* header_serialized, size_t headerlen, btc_block_header* header);
LIBBTC_API void btc_block_header_serialize(cstring* s, const btc_block_header* header);
LIBBTC_API void btc_block_header_copy(btc_block_header* dest, const btc_block_header* src);
LIBBTC_API btc_bool btc_block_header_hash(btc_block_header*header, uint8_t* hash);

#ifdef __cplusplus
}
#endif

#endif //__LIBBTC_BLOCK_H__
