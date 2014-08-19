#ifndef __WINTERNITZ_H
#define __WINTERNITZ_H

#include "sponge.h"

// Winternitz interface:

#define WINTERNITZ_OK 1
#define WINTERNITZ_ERROR 0


#define WINTERNITZ_SEC_LVL	128
#ifndef WINTERNITZ_W
	#define WINTERNITZ_W		2
#endif
#define WINTERNITZ_N            1*WINTERNITZ_SEC_LVL

#if WINTERNITZ_W > 8
#error the maximum w value is 8 due to chosen data type in this implementation
#endif

#define WINTERNITZ_l1 ((WINTERNITZ_N + WINTERNITZ_W - 1) / WINTERNITZ_W)
#if (WINTERNITZ_W == 2)
    #if WINTERNITZ_N == 128
	#define WINTERNITZ_l2 (4)
    #elif WINTERNITZ_N == 256
    	#define WINTERNITZ_l2 (5)
    #endif
#elif (WINTERNITZ_W == 4)
    #define WINTERNITZ_l2 (3) //l2=3 if l1 \in {32,64}
#elif (WINTERNITZ_W == 8)
    #define WINTERNITZ_l2 (2)
#endif
#define WINTERNITZ_CHECKSUM_SIZE (WINTERNITZ_l2)
#define WINTERNITZ_l (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)
#define WINTERNITZ_L (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)

//#define GET_CHUNK(x, startbit) ((x & (unsigned)( (unsigned)((1 << WINTERNITZ_W) - 1) << startbit)) >> startbit)
#define LEN_BYTES(len_bits) ((len_bits+7)/8)

void winternitz_keygen(const unsigned char s[], const unsigned short m, mmo_t *mmo, dm_t *f, unsigned char v[]);
void winternitz_sign(const unsigned char s[], const unsigned char v[], const unsigned short m, const char *M, unsigned short len, mmo_t *hash, dm_t *f, unsigned char h[], unsigned char sig[]);
unsigned char winternitz_verify(const unsigned char v[], const unsigned short m, const char *M, unsigned short len, mmo_t *hash, dm_t *f, unsigned char h[], const unsigned char sig[], unsigned char x[]);


#endif // __WINTERNITZ_H
