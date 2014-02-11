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

// sec level: 128
#define WINTERNITZ_SEC_LVL (128)
#define WINTERNITZ_W (8)


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

void winternitzGen(const byte s[/*m*/], const uint m, sponge_t *priv, sponge_t *hash, sponge_t *pubk, byte v[/*m*/]);
void winternitzSig(const byte s[/*m*/], const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *priv, sponge_t *hash, byte h[/*m*/], byte sig[/*(m+2)*m*/] /* m+2 m-byte blocks */);
bool winternitzVer(const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *pubk, sponge_t *hash, byte h[/*m*/], const byte sig[/*(2*m+3)*m*/] /* 2m+3 m-byte blocks */, byte x[/*m*/]);


#ifdef __cplusplus
};
#endif

#endif // __WINTERNITZ_H
