#ifndef __WINTERNITZ_H
#define __WINTERNITZ_H


#include "sponge.h"

// Winternitz interface:
#ifdef __cplusplus
extern "C" {
#endif


// w: word size in bits
// sec level = n - w - 1 - 2log_2(l*w) (security for pre-image resistance)

// sec level: 82
#define SEC (82)
#define W_BITS (3)
#define n (104)

// sec level: 86
//#define SEC (86)
//#define W_BITS (2)
//#define n (104)

// sec level: 97
//#define W_BITS (3)
//#define n (120)

// sec level: 101
//#define W_BITS (2)
//#define n (120)

// sec level: 129
//#define W_BITS (3)
//#define n (152)

// sec level: 126
//#define W_BITS (2)
//#define n (144)

#define W (1 << W_BITS)
#define l (n >> W_BITS)

typedef sponge_t oneway_state;
typedef unsigned char rand_dig_f_type(void);

void Display(const char *name, const unsigned char *u, short ud);
short Rand(unsigned char *x, short bits, rand_dig_f_type rand_dig_f);

void onewayfunction(oneway_state *f, unsigned char *input, short inputlen, unsigned char *output, short outputlen);
void onewayfunction_mult(oneway_state *f, short iter, unsigned char *input, short inputlen, unsigned char *output, short outputlen);
void wots_getprivkey(oneway_state *f, unsigned char s[l][(n+7)/8], unsigned char *seed, short seedd);
void wots_keygen(oneway_state *f, unsigned char s[l][(n+7)/8], unsigned char v[l][(n+7)/8], unsigned char *seed, short seedd);


#ifdef __cplusplus
};
#endif


#endif // __WINTERNITZ_H
