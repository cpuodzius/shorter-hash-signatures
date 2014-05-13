#ifndef __SPONGE_H
#define __SPONGE_H

#include "mmo.h"

typedef mmo_t sponge_t;

// Sponge interface:

void sinit(sponge_t *sponge, short seclevel);
void absorb(sponge_t *sponge, const void *data, short len);
void squeeze(sponge_t *sponge, void *digest, short len);
void cleanup(sponge_t *sponge);

void hash16(dm_t *dm, const unsigned char data[16], unsigned char digest[16]);
void hash32(dm_t *dm, const unsigned char data0[16], const unsigned char data1[16], unsigned char digest[16]);

#endif /* __SPONGE_H */
