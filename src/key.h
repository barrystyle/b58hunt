#ifndef B58GEN_KEY_H
#define B58GEN_KEY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <chrono>
#include <iostream>
#include <limits>

#include <secp256k1.h>

void generate_keypair(secp256k1_context* ctx, char* seckey, char* pubwif, char* pkh);
void genkey(char* privkey, uint64_t& smalnum);

#endif // B58GEN_KEY_H
