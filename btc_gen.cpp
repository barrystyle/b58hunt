// btcpuzzle keygen
// copyright (c) 2022 barrystyle

#include "util.h"
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <thread>
#include <vector>

static secp256k1_context* ctx = NULL;
unsigned char pubkey_hash[20] = { 0x3e, 0xe4, 0x13, 0x3d, 0x99, 0x1f, 0x52, 0xfd, 0xf6, 0xa2, 0x5c, 0x98, 0x34, 0xe0, 0x74, 0x5a, 0xc7, 0x42, 0x48, 0xa4 };

void generate_keypair(char* seckey, char* pubwif, char* pkh)
{
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    }

    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)seckey);

    uint8_t pubkey_serialized[33];
    size_t pubkeylen = sizeof(pubkey_serialized);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);

    unsigned char hash[32];
    SHA256(pubkey_serialized, pubkeylen, hash);
    RIPEMD160(hash, SHA256_DIGEST_LENGTH, (unsigned char*)pkh);
}

inline void genkey(char* privkey, uint64_t& smalnum)
{
    memset(privkey, 0, 32);
    uint64_t swapped = __builtin_bswap64(smalnum);
    memcpy(&privkey[24], &swapped, 8);
}

void scan(int thr_id, uint64_t range_override = 0)
{
    srand(time(NULL));

    int best = 0;
    int hashes = 0;
    char privkey[32];
    char pubkey[35];
    char pkh[20];
    uint64_t st = get_time_millis();
    uint64_t num = range_override;

    printf("[%2d] Scanning range %llx\n", thr_id, num);

    while (++num) {

        if (hashes++ > 500000) {

            uint64_t fn = get_time_millis();
            double diff = (double) (fn - st) / 1000;
            double hps = (double) hashes / diff;
            printf("[%2d] %.2f keys/sec\n", thr_id, hps);

            hashes = 0;
            st = get_time_millis();
        }

        genkey(&privkey[0], num);
        generate_keypair(&privkey[0], &pubkey[0], &pkh[0]);

        for (int z = 0; z < 20; z++) {
            if (pubkey_hash[z] != (uint8_t)pkh[z]) {
                break;
            }
            if (z > best) {
                char full_privkey[65];
                memset(full_privkey, 0, sizeof(full_privkey));
                for (int y = 0; y < 32; y++) {
                    sprintf(full_privkey + (y * 2), "%02hhx", privkey[y]);
                }
                best = z;
                printf("[%2d] best match %d (privkey %s)\n", thr_id, best + 1, full_privkey);
                if (best + 1 == 20) {
                    return;
                }
            }
        }
    }

    return;
}

#define THR_MAX 4

int main()
{
    std::srand(std::time(nullptr));
    uint64_t random_variable = std::rand();

    std::vector<std::thread> threads;

    uint64_t thr_range;
    std::vector<uint64_t> prev_start;
    uint64_t base_range = 0x8000000000000000;
    uint64_t sub_range = 0xffffffffffffffff;

    for (int i = 0; i < THR_MAX; i++) {
        while (true) {
            thr_range = 0;
            while (thr_range < base_range) {
                thr_range = base_range + (((sub_range - base_range) / std::rand()) * std::rand());
            }
            if (std::find(prev_start.begin(), prev_start.end(), thr_range) == prev_start.end()) {
                break;
            }
        }
        prev_start.push_back(thr_range);
        printf("launching thread %2d (%016llx)..\n", i, thr_range);
        threads.push_back(std::thread(scan, std::move(i), std::move(thr_range)));
    }

    for (auto& th : threads) {
        th.join();
    }

    return 1;
}
