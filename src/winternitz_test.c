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
    unsigned char privkey[WINTERNITZ_L][WINTERNITZ_l1], pubkey[WINTERNITZ_L][WINTERNITZ_l1], V[WINTERNITZ_l1], seed[(SEC+7)/8], S[WINTERNITZ_L][WINTERNITZ_l1];
    unsigned char M[WINTERNITZ_L];
    for(unsigned char i=0; i<WINTERNITZ_l1; i++) {
        M[i] = i;
    }

    printf("\n Parameters:  w=%u, n=%u, l1=%u, l2=%u, L=%u \n\n",WINTERNITZ_W,WINTERNITZ_N,WINTERNITZ_l1,WINTERNITZ_l2,WINTERNITZ_L);

    // Note that this function is not a secure pseudo-random function. It was only used for tests.
    //srand((unsigned int)time((time_t *)NULL));
    srand(0);
    short seedd = Rand(seed, SEC, rand_dig_f);
    Display("\n seed for keygen: ",seed,seedd);

    wots_keygen(&f, privkey, pubkey, V, seed, seedd);

    wots_sign(&f, M, privkey, S);

    if(wots_verify(&f, M, V, S) == OK) {
        printf("\n \n Signature is valid: \n \n");
    } else {
        printf("\n \n Signature is invalid: \n \n");
    }

    printf("(");
    Display("",S[0],WINTERNITZ_l1);
    for(unsigned char i=0; i<WINTERNITZ_L; i++) {
        Display(",",S[i],WINTERNITZ_l1);
    }
    printf(") \n \n");

}
