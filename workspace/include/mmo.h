#ifndef __MMO_H
#define __MMO_H

#ifdef PLATFORM_TELOSB
//#include "cc2420-aes.h"
//#include "cc2420-aes.c"
#include "TI_aes.h"
#include "TI_aes.c"
#else
//#include "aes.h"
#include "TI_aes.h"
#endif

/**
 * Encrypt a single AES block under a 128-bit key.
 */
void AES_encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16], unsigned char key[16]);


typedef struct {
    unsigned char H[16]; // hash chaining state
    unsigned char M[16]; // message block
    unsigned char IV[16]; // IV for davies meyer
    unsigned int t; // remaining space on M, in unsigned chars
    unsigned int n; // total message length
} mmo_t;


void MMO_init(mmo_t *mmo);

void MMO_update(mmo_t *mmo, const unsigned char *M, unsigned int m);

void MMO_final(mmo_t *mmo, unsigned char tag[16]);

void MMO_hash16(mmo_t *mmo, const unsigned char M[16], unsigned char tag[16]);

void MMO_hash32(mmo_t *mmo, const unsigned char M[32], unsigned char tag[16]);

void davies_meyer_init(mmo_t *mmo);

void davies_meyer_hash16(unsigned char IV[16], const unsigned char M[16], unsigned char tag[16]);

void davies_meyer_hash32(unsigned char IV[16], const unsigned char M0[16], const unsigned char M1[16], unsigned char tag[16]);

#endif // __MMO_H
