#include <stdlib.h>
#include <string.h>

#include "../include/sponge.h"

void sinit(sponge_t *sponge, short seclevel) {
    if (seclevel > (BLAKE2S_OUTBYTES << 3)) {
        seclevel = (BLAKE2S_OUTBYTES << 3); // maximum
    }
    if (sponge != NULL) {
        blake2s_init(sponge, seclevel >> 3);
    }
}

void absorb(sponge_t *sponge, const void *data, short len) {
    if (sponge != NULL) {
        blake2s_update(sponge, (uint8_t *)data, len);
    }
}

void squeeze(sponge_t *sponge, void *digest, short len) {
    if (sponge != NULL) {
        blake2s_final(sponge, digest, len);
    }
}

void cleanup(sponge_t *sponge) {
    if (sponge != NULL) {
        memset(sponge, 0, sizeof(sponge_t));
    }
}
