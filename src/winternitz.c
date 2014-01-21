#include <stdlib.h>

#include "../include/winternitz.h"

void onewayfunction(oneway_state *f, short iterations, XP_digit_t *input, XP_digit_t *output, short hashlen) {

  sinit(f, seclevel);

  absorb(f, input, seclevel);
  squeeze(f, output, seclevel);
  for(int i=1;i<iterations;i++) {
    absorb(f, output, seclevel);
    squeeze(f, output, hashlen);
  }

}

void keygen(oneway_state *f, XP_digit_t privkey[L], XP_digit_t pubkey[L], XP_digit_t *seed, short w, short seclevel) {
/*First we use the srand() function to seed the randomizer. Basically, the computer can generate random numbers based on the number that is fed to srand(). If you gave the same seed value, then the same random numbers would be generated every time.*/
    //srand(seed);
    //int r = rand();
    short iter = 1;

    //x_0 <= f(SEED)
    onewayfunction(f,iter,seed,privkey[0],seclevel);
    for(int i=1;i<L;i++) {
        onewayfunction(f,iter,privkey[i-1],privkey[i],seclevel);
    }




}
