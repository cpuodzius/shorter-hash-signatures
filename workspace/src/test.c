#include <stdio.h>
#include "test.h"

#ifdef PLATFORM_TELOSB
#include "sponge.h"
#include "sponge.c"
#include "winternitz.c"
#include "mss.c"
#include "mmo.c"
#endif

struct mss_node nodes[2];
struct state_mt state;
struct mss_node currentLeaf;
struct mss_node authpath[MSS_HEIGHT];
sponge_t sponges[2];
unsigned char pkey[NODE_VALUE_SIZE];
unsigned char seed[LEN_BYTES(MSS_SEC_LVL)];
unsigned char h1[LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char sig[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];
short errors, j;
char M[] = "Hello, world!";
		
int test_merkle_signature() {

	// Set seed
	for (j = 0; j < LEN_BYTES(MSS_SEC_LVL); j++) {
		seed[j] = 0xA0 ^ j; // sample private key, for debugging only
	}
	sinit(&sponges[0], MSS_SEC_LVL);
	sinit(&sponges[1], MSS_SEC_LVL);

	// Compute Merkle Public Key
	mss_keygen(&sponges[0] , &sponges[1], seed, &nodes[0], &nodes[1], &state, pkey);

	//Sign and verify for all j-th authentication paths
	errors = 0;
	for (j = 0; j < (1 << MSS_HEIGHT); j++) {
#ifdef DEBUG
	    printf("Testing merkle signature for leaf %d ...", j);
#endif
	    mss_sign(&state, seed, &currentLeaf, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], h1, j, &nodes[0], &nodes[1], sig, authpath);
        if(mss_verify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], h1, j, sig, aux, &currentLeaf, pkey) == MSS_OK) {
#ifdef DEBUG
            printf(" [OK]\n");
#endif
	    } else {
            errors++;
#ifdef DEBUG
            printf(" [ERROR]\n");
#endif
	    }
	}

	return errors;
}

int do_test(enum TEST operation) {
	unsigned char ret = 0;

	switch(operation) {
		case TEST_MSS_SIGN:
			ret = test_merkle_signature();
#ifdef MSS_SELFTEST
            printf("Errors: %d \n", ret);
#endif
			break;
	}
	return ret;
}

