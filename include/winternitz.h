#ifndef __WINTERNITZ_H
#define __WINTERNITZ_H


#include "sponge.h"

// Winternitz interface:
#ifdef __cplusplus
extern "C" {
#endif

#define OK 0
#define ERROR 1

// WINTERNITZ_W: word size in bits
// WINTERNITZ_SEC_LVL = WINTERNITZ_N - WINTERNITZ_W - 1 - 2log_2(WINTERNITZ_L*WINTERNITZ_W) (security for pre-image resistance)

// sec level: 82
#define WINTERNITZ_SEC_LVL (82)
#define WINTERNITZ_W (8)
#define WINTERNITZ_N (104)

// sec level: 86
//#define WINTERNITZ_SEC (86)
//#define WINTERNITZ_W (4)
//#define WINTERNITZ_N (104)

// sec level: 97
//#define W_BITS (8)
//#define WINTERNITZ_N (120)

// sec level: 101
//#define WINTERNITZ_W (4)
//#define WINTERNITZ_N (120)

// sec level: 129
//#define WINTERNITZ_W (8)
//#define WINTERNITZ_N (152)

// sec level: 126
//#define WINTERNITZ_W (4)
//#define WINTERNITZ_N (144)

#define TwotoW (1 << WINTERNITZ_W)
//TODO: Find the smallest possible checksum size
#define WINTERNITZ_CHECKSUM_SIZE 2
#define WINTERNITZ_l1 ( (WINTERNITZ_N + WINTERNITZ_W - 1) / WINTERNITZ_W)
#define WINTERNITZ_l2 (WINTERNITZ_CHECKSUM_SIZE)
#define WINTERNITZ_l (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)
#define WINTERNITZ_L (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)

#define GetWBits(x, startbit) ((x & (unsigned)( (unsigned)((1 << WINTERNITZ_W) - 1) << startbit)) >> startbit)
#define LEN_BYTES(len_bits) ((len_bits+7)/8)

typedef sponge_t oneway_state;
typedef unsigned char rand_dig_f_type(void);

void Display(const char *name, const unsigned char *u, short ud);
short Rand(unsigned char *x, short bits, rand_dig_f_type rand_dig_f);

void onewayfunc(oneway_state *f, unsigned char *input, short inputlen, unsigned char *output, short outputlen);
void onewayfunc_mult(oneway_state *f, short iter, unsigned char *input, short inputlen, unsigned char *output, short outputlen);

void wots_getprivkey(oneway_state *f, unsigned char s[WINTERNITZ_L][WINTERNITZ_l1], unsigned char *seed, short seedd);
void wots_keygen(oneway_state *f, unsigned char s[WINTERNITZ_L][WINTERNITZ_l1], unsigned char v[WINTERNITZ_L][WINTERNITZ_l1], unsigned char V[WINTERNITZ_l1], unsigned char *seed, short seedd);
void wots_computechecksum(unsigned char M[WINTERNITZ_L]);
unsigned char wots_sign(oneway_state *f, unsigned char M[WINTERNITZ_L], unsigned char s[WINTERNITZ_L][WINTERNITZ_l1], unsigned char S[WINTERNITZ_L][WINTERNITZ_l1]);
unsigned char wots_verify(oneway_state *f, unsigned char m[WINTERNITZ_L], unsigned char V[WINTERNITZ_l1], unsigned char S[WINTERNITZ_L][WINTERNITZ_l1]);

#ifdef __cplusplus
};
#endif


#endif // __WINTERNITZ_H
