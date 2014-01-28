#include <stdlib.h>
#include <stdio.h>

#include "../include/winternitz.h"


void Display(const char *name, const unsigned char *u, short ud) {
    short i, j;
    //assert(ud >= 0);
    printf("%s", name);
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

/**
 * Returns -1, 0, or +1 if u < v, u = v, or u > v, respectively
 */
short Comp(const unsigned char *u, short ud, const unsigned char *v, short vd) {
    short i;
    //assert(ud >= 0);
    //assert(vd >= 0);
    if (ud < vd) {
        return -1;
    }
    if (ud > vd) {
        return +1;
    }
    // ud == vd
    for (i = ud - 1; i >= 0; i--) {
        if (u[i] < v[i]) {
            return -1;
        }
        if (u[i] > v[i]) {
            return +1;
        }
    }
    return 0;
}

/**
 * @param inputlen      The size of input in bytes
 * @param outputlen     The size of output in bytes
 */
void onewayfunc(oneway_state *f, unsigned char *input, short inputlen, unsigned char *output, short outputlen) {

    sinit(f, SEC);
    absorb(f, input, inputlen);
    squeeze(f, output, outputlen);
    cleanup(f);
}

/**
 * @param inputlen      The input size in bytes
 * @param outputlen     The output size in bytes
 */
void onewayfunc_mult(oneway_state *f, short iter, unsigned char *input, short inputlen, unsigned char *output, short outputlen) {

    unsigned char i;

    if(iter == 0) {
        for (i = 0; i < inputlen; i++) {
            output[i] = input[i];
        }
        return;
    }

    onewayfunc(f, input, inputlen, output, outputlen);
    for(i=1; i<iter; i++) {
        onewayfunc(f, output, outputlen, output, outputlen);
    }
}

/**
 * Compute private elements si's from the seed
 *
 * @param f         The oneway function
 * @param s         The expanded private key (s_0, ..., s_{L-1}), where |s_i| = l*w bits
 * @param seed      The seed for the oneway function. It is the actual private key to be stored.
 * @param seedd     The size of the seed in digits
 */
void wots_getprivkey(oneway_state *f, unsigned char s[L][l1], unsigned char *seed, short seedd) {

    unsigned char i;

    // Initializes the oneway function
    sinit(f, SEC);

    // Feed the sponge with the seed
    absorb(f, seed, seedd);

    // Compute private key (s_0, ..., s_{L-1})
    squeeze(f, &s[0], l1);
    for(i=1; i<L; i++) {
        squeeze(f, &s[i], l1);
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
void wots_keygen(oneway_state *f, unsigned char s[L][l1], unsigned char v[L][l1], unsigned char V[l1], unsigned char *seed, short seedd) {

    unsigned char i;

    // Compute private key s from the seed
    wots_getprivkey(f, s, seed, seedd);

    // Compute public key components vi's from private key si's
    for(i=0; i<L; i++) {
        onewayfunc_mult(f, TwotoW-1, s[i], l1, v[i], l1);
    }

    // Compute v = H(v_0||v_1||...||v_{L-1})
    sinit(f, SEC);
    for(i=0; i<L; i++) {
        absorb(f, v[i], l1);
    }
    squeeze(f, V, l1);
    cleanup(f);
}

void wots_computechecksum(unsigned char M[L]) {

    unsigned char i;
    short cs = 0;

    for(i=0; i<l1; i++) {
        cs += TwotoW - 1 - M[i];
    }

    // Fill the message representative with the checksum
    for(i=l1; i<L; i++) {
        M[i] = GetWBits(cs, (i-l1)*W);
    }
}

unsigned char wots_sign(oneway_state *f, unsigned char M[L], unsigned char s[L][l1], unsigned char S[L][l1]) {

    unsigned char i;

    wots_computechecksum(M);

    Display("\n Message representative with checksum:",M,L);

    // Compute the signature (S_0,S_1,...,S_{L-1})
    for(i=0; i<L; i++) {
        onewayfunc_mult(f, TwotoW-1-M[i], s[i], l1, S[i], l1);
    }

    return OK;
}

unsigned char wots_verify(oneway_state *f, unsigned char m[L], unsigned char V[l1], unsigned char S[L][l1]) {

    unsigned char i, t[L][l1];

    for(i=0; i<L; i++) {
        onewayfunc_mult(f,m[i],S[i],l1,t[i],l1);
    }

    // Compute t = H(t_0||t_1||...||t_{L-1})
    sinit(f, SEC);
    for(i=0; i<L; i++) {
        absorb(f, t[i], l1);
    }
    squeeze(f, t[0], l1); // reuse memory
    cleanup(f);

    // Compare if t equals V
    if(Comp(t[0], l1, V, l1) != 0) {
        return ERROR;
    }

    return OK;
}
