#ifndef __SPONGE_H
#define __SPONGE_H

#ifndef __USUAL_TYPES
#define __USUAL_TYPES
typedef unsigned char  bool;
typedef unsigned char  byte;
typedef unsigned short uint;
#endif /* __USUAL_TYPES */

#include "blake2.h"

typedef blake2s_state sponge_t;

// Sponge interface:
#ifdef __cplusplus
extern "C" {
#endif

void sinit(sponge_t *sponge, short seclevel);
void absorb(sponge_t *sponge, const void *data, short len);
void squeeze(sponge_t *sponge, void *digest, short len);
void cleanup(sponge_t *sponge);

#ifdef __cplusplus
};
#endif

#endif /* __SPONGE_H */
