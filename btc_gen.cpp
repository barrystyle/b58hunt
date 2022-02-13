// btcpuzzle keygen
// copyright (c) 2022 barrystyle

#include "util.h"
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <thread>
#include <vector>

typedef unsigned char byte;
static secp256k1_context* ctx = NULL;
static const char* tmpl = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char* base58(byte* s, int s_size, char* out, int out_size)
{
    int c, i, n;
    out[n = out_size] = 0;
    while (n--) {
        for (c = i = 0; i < s_size; i++) {
            c = c * 256 + s[i];
            s[i] = c / 58;
            c %= 58;
        }
        out[n] = tmpl[c];
    }
    return out;
}

void generate_keypair(char* seckey, char* pubwif)
{
    if (!ctx)
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char*)seckey);

    uint8_t pubkey_serialized[33];
    size_t pubkeylen = sizeof(pubkey_serialized);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);

    byte s[33];
    char pubaddress[34];
    byte rmd[5 + RIPEMD160_DIGEST_LENGTH];
    for (int j = 0; j < 33; j++) { s[j] = pubkey_serialized[j]; }

    rmd[0] = 0;
    RIPEMD160(SHA256(s, 33, 0), SHA256_DIGEST_LENGTH, rmd + 1);
    memcpy(rmd + 21, SHA256(SHA256(rmd, 21, 0), SHA256_DIGEST_LENGTH, 0), 4);

    char address[34];
    base58(rmd, 25, address, 34);

    int n;
    for (n = 0; address[n] == '1'; n++);
    if (n > 1) {
        memmove(address, address + (n - 1), 34 - (n - 1));
        pubaddress[34 - (n - 1)] = '\0';
    }
    memcpy(pubwif, address, 34);
    memset(pubwif + 34, 0, 1);
}

void genkey(char* privkey, uint64_t& smalnum)
{
    memset(privkey, 0, 32);
    uint64_t swapped = __builtin_bswap64(smalnum);
    memcpy(&privkey[24], &swapped, 8);
}

void scan(char matchkey[34], int thr_id, uint64_t range_override = 0)
{
    srand(time(NULL));

    char privkey[32];
    char pubkey[35];

    int duration = 10;
    uint64_t num = range_override;

    return_on_sec();
    int64_t start = get_time_millis();
    int64_t over_start = get_time_millis();

    int x = 0;
    int best = 0;
    uint64_t totalkeys = 0;

    printf("[%d] Scanning range %llx\n", thr_id, num);

    while (true) {

        totalkeys++;
        x++;

        ++num;
        genkey(&privkey[0], num);
        generate_keypair(&privkey[0], &pubkey[0]);

        const auto checkpt = get_time_millis();

        if (checkpt - start > duration * 1000) {
            printf("[%d] %.2f pairs/s (tested %llu keys)\n", thr_id, float(x / duration), totalkeys);
            start = checkpt;
            x = 0;
        }

        for (int z = 0; z < 34; z++) {
            if (pubkey[z] != matchkey[z]) {
                break;
            }
            if (z > best) {
                char full_privkey[65];
                memset(full_privkey, 0, sizeof(full_privkey));
                for (int y = 0; y < 32; y++)
                    sprintf(full_privkey + (y * 2), "%02hhx", privkey[y]);
                best = z;
                printf("[%d] best match %d (ours %s, tomatch %s - privkey %s)\n", thr_id, best + 1, pubkey, matchkey, full_privkey);
                if (best + 1 == 34)
                    return;
            }
        }
    }

    return;
}

#define THR_MAX 4

int main()
{
#if 0
    //! test using the previous puzzles
    bool unit_tests = false;
    if (unit_tests) {
	scan("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
	scan("1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb");
	scan("19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA");
	scan("1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e");
	scan("1E6NuFjCi27W5zoXg8TRdcSRq84zJeBW3k");
	scan("1PitScNLyp2HCygzadCh7FveTnfmpPbfp8");
	scan("1McVt1vMtCC7yn5b9wgX1833yCcLXzueeC");
	scan("1M92tSqNmQLYw33fuBvjmeadirh1ysMBxK");
	scan("1CQFwcjw1dwhtkVWBttNLDtqL7ivBonGPV");
	scan("1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe");
	scan("1PgQVLmst3Z314JrQn5TNiys8Hc38TcXJu");
	scan("1DBaumZxUkM4qMQRt2LVWyFJq5kDtSZQot");
	scan("1Pie8JkxBT6MGPz9Nvi3fsPkr2D8q3GBc1");
	scan("1ErZWg5cFCe4Vw5BzgfzB74VNLaXEiEkhk");
	scan("1QCbW9HWnwQWiQqVo5exhAnmfqKRrCRsvW");
	scan("1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY");
	scan("1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm");
	scan("1GnNTmTVLZiqQfLbAdp9DVdicEnB5GoERE");
	scan("1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w");
	scan("1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum");
    }
#endif

    std::vector<std::thread> threads;
    uint64_t base_range = 0x8000000000000000;
    uint64_t sub_range = 0x1000000000000000;

    char test_addr[35];
    memset(test_addr, 0, sizeof(test_addr));
    sprintf(test_addr, "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN");

    for (int i = 0; i < THR_MAX; i++) {
        uint64_t thr_range = base_range + (i * sub_range);
        printf("launching thread %d (%016llx)..\n", i, thr_range);
        threads.push_back(std::thread(scan, std::move(test_addr), std::move(i), std::move(thr_range)));
    }

    for (auto& th : threads) {
        th.join();
    }

    return 1;
}
