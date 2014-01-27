#include <stdlib.h>
#include <stdio.h>

#include "../include/winternitz.h"


void Display(const char *name, const unsigned char *u, short ud) {
    short i, j;
    //assert(ud >= 0);
    printf("%s[%d]:", name, ud);
    if (ud > 0) {
        for (i = ud - 1, j = 0; i >= 0; i--, j++) {
            printf("%s%02X%s", (j % (2*(n/8))) ? "" : "\t", u[i], ((j+1) % (2*(n/8))) ? "" : "\n");
        }
    } else {
        printf("\t%02X", 0);
    }
    printf("\n");
}

short Rand(unsigned char *x, short bits, rand_dig_f_type rand_dig_f) {
    short i, xd = (bits + W - 1)/W;
    for (i = 0; i < xd; i++) {
        x[i] = rand_dig_f();
    }
    i = (bits % W);
    if (xd > 0 && i > 0) {
        x[xd - 1] &= (unsigned char)(1 << i) - 1;
    }
    while (xd > 0 && x[xd - 1] == 0) {
        xd--;
    }
    return xd;
}

void onewayfunction(oneway_state *f, unsigned char *input, short inputlen, unsigned char *output, short outputlen) {

    sinit(f, SEC);
    absorb(f, input, inputlen);
    squeeze(f, output, outputlen);
    cleanup(f);
}

void onewayfunction_mult(oneway_state *f, short iter, unsigned char *input, short inputlen, unsigned char *output, short outputlen) {

    sinit(f, SEC);
    absorb(f, input, inputlen);
    squeeze(f, output, outputlen);
    for(int i=0; i<iter; i++) {
        absorb(f, output, outputlen);
        squeeze(f, output, outputlen);
    }
    cleanup(f);
}

/**
 * Compute private elements si's from the seed
 *
 * @param f         The oneway function
 * @param s         The expanded private key (s_0, ..., s_{L-1}), where |s_i| = l*w bits
 * @param seed      The seed for the oneway function. It is the actual private key to be stored.
 * @param seedd     The size of the seed in digits
 */
void wots_getprivkey(oneway_state *f, unsigned char s[l][(n+7)/8], unsigned char *seed, short seedd) {

    // Initializes the oneway function
    sinit(f, SEC);

    // Feed the sponge with the seed
    absorb(f, seed, seedd);
    //printf("\n sponge: \n");
    //for(unsigned char i = 0; i < f->buflen; i++) {
    //    printf("%02x", f->buf[i]);
    //}


    // Compute private key (s_0, ..., s_{L-1})
    squeeze(f, &s[0], (n+7)>>3);
    for(short i = 1; i < l; i++) {
        squeeze(f, &s[i], (n+7)>>3);
    }
    cleanup(f);
}

/**
 * Winternitz key generation algorithm
 *
 * @param f         The oneway function
 * @param s         The expanded private key (s_0, ..., s_{L-1}), where |s_i| = l*w bits
 * @param v         The Wintenitz public key v = (v_0,...,v_{L-1}), where |v_i| = l*w bits
 * @param seed      The seed for the oneway function. It is the actual private key to be stored.
 * @param seedd     The size of the seed in digits
 */
void wots_keygen(oneway_state *f, unsigned char s[l][(n+7)/8], unsigned char v[l][(n+7)/8], unsigned char *seed, short seedd) {


    // Compute private key
    wots_getprivkey(f, s, seed, seedd);

    // Compute public key v = H(v_0 || ... || v_{l-1})
    for(short i = 0; i < l; i++) {
        onewayfunction(f, s[i], (n+7)>>3, v[i], (n+7)>>3);
    }

    //TODO: compute v = H(v_0||v_1||...||v_{L-1})

}
