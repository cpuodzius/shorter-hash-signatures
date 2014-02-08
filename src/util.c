#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include "winternitz.h"

unsigned char rand_dig_f(void) {
    return (unsigned char)rand();
}

void Display(const char *tag, const byte *u, uint n) {
    uint i;
    printf("%s:\n", tag);
    for (i = 0; i < n; i++) {
        printf("%02X", u[i]);
    }
    printf("\n\n");
}


short Rand(unsigned char *x, short bits, rand_dig_f_type rand_dig_f) {
    short i, xd = (bits + 7 - 1)/8;
    for (i = 0; i < xd; i++) {
        x[i] = rand_dig_f();
    }
    i = (bits % WINTERNITZ_W);
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

