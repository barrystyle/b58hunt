// btcpuzzle keygen
// copyright (c) 2022 barrystyle

#include "key.h"

#include <secp256k1.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

//! albertos hashfuncs
#include "sha256.h"
#include "ripemd160.h"

void generate_keypair(secp256k1_context* ctx, char* seckey, char* pubwif, char* pkh)
{
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)seckey);

    uint8_t pubkey_serialized[33];
    size_t pubkeylen = sizeof(pubkey_serialized);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);

    unsigned char hash[32];
    sha256_33(pubkey_serialized, hash);
    ripemd160_32(hash, (unsigned char*)pkh);
}

void genkey(char* privkey, uint64_t& smalnum)
{
    memset(privkey, 0, 32);
    uint64_t swapped = __builtin_bswap64(smalnum);
    memcpy(&privkey[24], &swapped, 8);
}
