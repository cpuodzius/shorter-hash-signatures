#ifndef __SPONGE_H
#define __SPONGE_H


#ifdef USE_BLAKE2S
#include "blake2.h"

typedef blake2s_state sponge_t;
#else
#include "mmo.h"

typedef mmo_t sponge_t;
#endif

#ifndef __USUAL_TYPES
#define __USUAL_TYPES
#ifndef PLATFORM_TELOSB
typedef unsigned char  bool;
typedef unsigned char  byte;
typedef unsigned short uint;
#endif
#endif /* __USUAL_TYPES */

// Sponge interface:
#ifdef __cplusplus
extern "C" {
#endif

void sinit(sponge_t *sponge, short seclevel);
void absorb(sponge_t *sponge, const void *data, short len);
void squeeze(sponge_t *sponge, void *digest, short len);
void cleanup(sponge_t *sponge);

void hash16(sponge_t *sponge, const unsigned char data[16], unsigned char digest[16]);
void hash32(sponge_t *sponge, const unsigned char data0[16], const unsigned char data1[16], unsigned char digest[16]);

#ifdef __cplusplus
};
#endif

#endif /* __SPONGE_H */
