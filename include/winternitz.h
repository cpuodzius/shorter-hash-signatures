#ifndef __WINTERNITZ_H
#define __WINTERNITZ_H


#include "sponge.h"

// Winternitz interface:
#ifdef __cplusplus
extern "C" {
#endif

#define OK 0
#define ERROR 1

// w: word size in bits
// sec level = n - w - 1 - 2log_2(l*w) (security for pre-image resistance)

// sec level: 82
#define SEC (82)
#define W (8)
#define n (104)

// sec level: 86
//#define SEC (86)
//#define W (4)
//#define n (104)

// sec level: 97
//#define W_BITS (8)
//#define n (120)

// sec level: 101
//#define W (4)
//#define n (120)

// sec level: 129
//#define W (8)
//#define n (152)

// sec level: 126
//#define W (4)
//#define n (144)

#define TwotoW (1 << W)
#define l1 ( (n + W - 1) / W)
//TODO: Find the smallest possible checksum size
#define CSSize 2
#define l2 (CSSize)
#define l (l1 + CSSize)
#define L (l1 + CSSize)

#define GetWBits(x, startbit) ((x & (unsigned)( (unsigned)((1 << W) - 1) << startbit)) >> startbit)

typedef sponge_t oneway_state;
typedef unsigned char rand_dig_f_type(void);

void Display(const char *name, const unsigned char *u, short ud);
short Rand(unsigned char *x, short bits, rand_dig_f_type rand_dig_f);

void onewayfunc(oneway_state *f, unsigned char *input, short inputlen, unsigned char *output, short outputlen);
void onewayfunc_mult(oneway_state *f, short iter, unsigned char *input, short inputlen, unsigned char *output, short outputlen);

void wots_getprivkey(oneway_state *f, unsigned char s[L][l1], unsigned char *seed, short seedd);
void wots_keygen(oneway_state *f, unsigned char s[L][l1], unsigned char v[L][l1], unsigned char V[l1], unsigned char *seed, short seedd);
void wots_computechecksum(unsigned char M[L]);
unsigned char wots_sign(oneway_state *f, unsigned char M[L], unsigned char s[L][l1], unsigned char S[L][l1]);
unsigned char wots_verify(oneway_state *f, unsigned char m[L], unsigned char V[l1], unsigned char S[L][l1]);

#ifdef __cplusplus
};
#endif


#endif // __WINTERNITZ_H
