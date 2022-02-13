#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <util.h>

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

    char pubaddress[34];
    byte s[33];
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
    memcpy(&privkey[0], &smalnum, 8);
}

uint64_t new_range()
{
    uint64_t MAX_RANGE = 0x8000000000000000;
    uint64_t ret = MAX_RANGE;

    char temp[8];
    memset(temp, 0, sizeof(temp));
    memcpy(temp, &MAX_RANGE, 8);

    for (int i = 7; i > -1; i--) {
        uint8_t rand_new;
        if (i == 7)
            rand_new = rand() % 63 + 1;
        else
            rand_new = rand() % 127 + 1;
        temp[i] += rand_new;
    }

    memcpy(&ret, temp, 8);

    return ret;
}

void scan()
{

    srand(time(NULL));

    char privkey[32];
    char pubkey[35];
    char matchkey[35];
    memset(matchkey, 0, 35);
    sprintf(matchkey, "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN");

    int duration = 10;
    uint64_t num = new_range();

    return_on_sec();
    int64_t start = get_time_millis();
    int64_t over_start = get_time_millis();

    int x = 0;
    int best = 0;
    uint64_t totalkeys = 0;

    printf("scanning range %llx\n", num);

    while (true) {

        totalkeys++;
        x++;

        ++num;
        genkey(&privkey[0], num);
        generate_keypair(&privkey[0], &pubkey[0]);

        const auto checkpt = get_time_millis();

        if (checkpt - start > duration * 1000) {
            printf("%.2f pairs/sec (tested %llu keys)\n", float(x / duration), totalkeys);
            start = checkpt;
            x = 0;
        }

        for (int z = 0; z < 34; z++) {

            if (pubkey[z] != matchkey[z]) {
                break;
            }

            if (z > best) {
                for (int y = 31; y > -1; y--) {
                    printf("%02hhx", privkey[y]);
                }
                printf("\n");
                best = z;
                printf("best match %d (ours %s, tomatch %s)\n", best, pubkey, matchkey);
            }
        }
    }

    return;
}

int main()
{

    while (true) {
        scan();
    }

    return 1;
}
