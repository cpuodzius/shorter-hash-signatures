#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "../include/winternitz.h"


unsigned char rand_dig_f(void) {
    return (unsigned char)rand();
}


int main(int argc, char *argv[]) {

    oneway_state f;
    unsigned char privkey[l][(n+7)/8], pubkey[l][(n+7)/8], seed[(SEC+7)/8];

    // Note that this function is not a cryptographically secure pseudo-random function. Only used for tests.
    //srand((unsigned int)time((time_t *)NULL));
    srand(0);
    short seedd = Rand(seed, SEC, rand_dig_f);
    Display("\n seed",seed,seedd);
    //printf("\n seed digits:%u",seedd);

    wots_keygen(&f, privkey, pubkey, seed, seedd);

    //*/
    printf("\n \n");
    for(short i = 0; i < l; i++) {
        Display("privkey:", privkey[i], l);
    }
    for(short i = 0; i < l; i++) {
        Display("pubkey:", pubkey[i], l);
    }
    //*/

}
