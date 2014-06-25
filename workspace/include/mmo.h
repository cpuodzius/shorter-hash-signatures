#ifndef __MMO_H
#define __MMO_H

#ifdef PLATFORM_TELOSB
	#ifdef AES_HW
		#include "cc2420-aes.h"
	#elif defined(AES_ASM)
		#include "aes.h"
	#else
		#include "TI_aes.h"
		//#include "TI_aes_128_encr_only.h"
		//#include "aes_avr.c"
	#endif
#else
	#include "TI_aes.h"
	//#include "TI_aes_128_encr_only.h"
#endif


typedef struct {
    unsigned char H[16]; // hash chaining state
    unsigned char M[16]; // message block
    unsigned int t; // remaining space on M, in unsigned chars
    unsigned int n; // total message length
} mmo_t;

typedef struct {
    unsigned char AES_KEY[16];
} dm_t; //davies-meyer

/**
 * Encrypt a single AES block under a 128-bit key.
 */
void AES_encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16], unsigned char key[16]);

void DM_init(dm_t *dm);

void MMO_init(mmo_t *mmo);

void MMO_update(mmo_t *mmo, const unsigned char *M, unsigned int m);

void MMO_final(mmo_t *mmo, unsigned char tag[16]);

void MMO_hash16(mmo_t *mmo, const unsigned char M[16], unsigned char tag[16]);

void MMO_hash32(mmo_t *mmo, const unsigned char M[32], unsigned char tag[16]);

void davies_meyer_init(mmo_t *mmo);

void davies_meyer_hash16(dm_t *dm, const unsigned char M[16], unsigned char tag[16]);

void davies_meyer_hash32(dm_t *dm, const unsigned char M0[16], const unsigned char M1[16], unsigned char tag[16]);

//forward secure pseudo-random generator
//short fsprg_counter = 0;
//void fsprg(unsigned char seed[16], unsigned char out1[16], unsigned char out2[32]);
//void fsprg_restart();

void prg16(short input, unsigned char seed[16], unsigned char output[16]);

#endif // __MMO_H
