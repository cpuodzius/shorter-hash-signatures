#ifndef __WINTERNITZ_H
#define __WINTERNITZ_H


#include "sponge.h"

// Winternitz interface:

#define OK 0
#define ERROR 1


// sec level: 128
#define WINTERNITZ_SEC_LVL (128)
#define WINTERNITZ_W (2)         // word size in bits


// sec level: 82
//#define WINTERNITZ_SEC_LVL (82)
//#define WINTERNITZ_W (8)
//#define WINTERNITZ_N (104)

// sec level: 86
//#define WINTERNITZ_SEC_LVL (86)
//#define WINTERNITZ_SEC (86)
//#define WINTERNITZ_W (4)
//#define WINTERNITZ_N (104)

// sec level: 97
//#define WINTERNITZ_SEC_LVL (97)
//#define W_BITS (8)
//#define WINTERNITZ_N (120)

// sec level: 101
//#define WINTERNITZ_SEC_LVL (101)
//#define WINTERNITZ_W (4)
//#define WINTERNITZ_N (120)

// sec level: 129
//#define WINTERNITZ_SEC_LVL (129)
//#define WINTERNITZ_W (8)
//#define WINTERNITZ_N (152)

// sec level: 126
//#define WINTERNITZ_SEC_LVL (126)
//#define WINTERNITZ_W (4)
//#define WINTERNITZ_N (144)


#define WINTERNITZ_l1 ((WINTERNITZ_SEC_LVL + WINTERNITZ_W - 1) / WINTERNITZ_W)
#if (WINTERNITZ_W == 2)
    #define WINTERNITZ_l2 (4)
#elif (WINTERNITZ_W == 4)
    #define WINTERNITZ_l2 (3)
#elif (WINTERNITZ_W == 8)
    #define WINTERNITZ_l2 (2)
#endif
#define WINTERNITZ_CHECKSUM_SIZE (WINTERNITZ_l2)
#define WINTERNITZ_l (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)
#define WINTERNITZ_L (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)

#define GetWBits(x, startbit) ((x & (unsigned)( (unsigned)((1 << WINTERNITZ_W) - 1) << startbit)) >> startbit)
#define LEN_BYTES(len_bits) ((len_bits+7)/8)

void winternitzGen(const unsigned char s[/*m*/], const unsigned short m, sponge_t *priv, sponge_t *hash, sponge_t *pubk, unsigned char v[/*m*/]);
void winternitzSig(const unsigned char s[/*m*/], const unsigned char v[/*m*/], const unsigned short m, const unsigned char *M, unsigned short len, sponge_t *priv, sponge_t *hash, unsigned char h[/*m*/], unsigned char sig[/*(m+2)*m*/] /* m+2 m-unsigned char blocks */);
unsigned char winternitzVer(const unsigned char v[/*m*/], const unsigned short m, const unsigned char *M, unsigned short len, sponge_t *pubk, sponge_t *hash, unsigned char h[/*m*/], const unsigned char sig[/*(2*m+3)*m*/] /* 2m+3 m-unsigned char blocks */, unsigned char x[/*m*/]);


#endif // __WINTERNITZ_H
