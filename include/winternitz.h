#ifndef __WINTERNITZ_H
#define __WINTERNITZ_H


#include "sponge.h"
#include "xp.h"

// Winternitz interface:
#ifdef __cplusplus
extern "C" {
#endif

// The word size in bits
#define W (4)
// Hash Output Size
#define HASHSIZE (128)
#define L (HASHSIZE >> 4)

typedef sponge_t oneway_state;

void onewayfunction(oneway_state *f, short iterations, XP_digit_t *input, XP_digit_t *output, short seclevel);
void keygen(oneway_state *f, XP_digit_t privkey[L], XP_digit_t pubkey[L], XP_digit_t *seed, short w, short seclevel);


#ifdef __cplusplus
};
#endif


#endif // __WINTERNITZ_H
