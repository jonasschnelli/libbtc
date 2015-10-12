#include "secp256k1/include/secp256k1.h"

#include <stdint.h>
#include <string.h>

#include "flags.h"

static secp256k1_context* secp256k1_ctx = NULL;

void ecc_context_init(void)
{
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

int ecc_isValid(uint8_t *private_key)
{
    if (!secp256k1_ctx) {
        ecc_context_init();
    }
    return (secp256k1_ec_seckey_verify(secp256k1_ctx, (const unsigned char *)private_key));
}

int ecc_generate_private_key(uint8_t *private_child, const uint8_t *private_master,
                             const uint8_t *z)
{
    memcpy(private_child, private_master, 32);
    return secp256k1_ec_privkey_tweak_add(secp256k1_ctx, (unsigned char *)private_child,
                                          (const unsigned char *)z);
}

static void ecc_get_pubkey(const uint8_t *private_key, uint8_t *public_key,
                           int public_key_len, int compressed)
{
    secp256k1_pubkey pubkey;

    memset(public_key, 0, public_key_len);

    if (!secp256k1_ctx) {
        ecc_context_init();
    }

    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey, (const unsigned char *)private_key)) {
        return;
    }

    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key, (size_t *)&public_key_len, &pubkey,
                                       compressed)) {
        return;
    }

    return;
}

void ecc_get_public_key65(const uint8_t *private_key, uint8_t *public_key)
{
    ecc_get_pubkey(private_key, public_key, 65, 0);
}


void ecc_get_public_key33(const uint8_t *private_key, uint8_t *public_key)
{
    ecc_get_pubkey(private_key, public_key, 33, 1);
}

int ecc_pubkey_tweak_add(uint8_t *public_key_inout, const uint8_t *tweak)
{
    int out, res;
    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key_inout, 33))
        return BTC_ERR;

    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &pubkey, (const unsigned char *)tweak))
        return BTC_ERR;

    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key_inout, (size_t *)&out, &pubkey,
                                  SECP256K1_EC_COMPRESSED))
        return BTC_ERR;

    return BTC_OK;
}