#include <stdlib.h>
#include <string.h>

#include "sponge.h"

void sinit(sponge_t *sponge, short seclevel) {

    MMO_init(sponge);
    /*
    if (seclevel > (BLAKE2S_OUTBYTES << 3)) {
        seclevel = (BLAKE2S_OUTBYTES << 3); // maximum
    }
    if (sponge != NULL) {
        blake2s_init(sponge, seclevel >> 3);
    }//*/
}

void absorb(sponge_t *sponge, const void *data, short len) {
    if (sponge != NULL) {
        //blake2s_update(sponge, (uint8_t *)data, len);
        MMO_update(sponge, data, len);
    }
}

void squeeze(sponge_t *sponge, void *digest, short len) {
    if (sponge != NULL) {
        //blake2s_final(sponge, digest, len);
        MMO_final(sponge, digest);
    }
}

void cleanup(sponge_t *sponge) {
    if (sponge != NULL) {
        memset(sponge, 0, sizeof(sponge_t));
    }
}

void hash16(sponge_t *sponge, const unsigned char data[16], unsigned char digest[16]) {
    if (sponge != NULL) {	
        davies_meyer_hash16(sponge->IV, data, digest);
    }
}

void hash32(sponge_t *sponge, const unsigned char data0[16], const unsigned char data1[16], unsigned char digest[16]) {
    if (sponge != NULL) {
        davies_meyer_hash32(sponge->IV, data0, data1, digest);
    }
}
