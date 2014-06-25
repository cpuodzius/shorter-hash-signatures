#include <stdio.h>
#include <string.h>
#include "test.h"

#ifdef PLATFORM_TELOSB
#include "sponge.h"
#include "sponge.c"
#include "winternitz.c"
#include "mss.c"
#include "mmo.c"
#endif

struct mss_node nodes[2];
struct state_mt state_test;
struct mss_node currentLeaf_test;
struct mss_node authpath_test[MSS_HEIGHT];
mmo_t hash_mmo;
dm_t f_test;
#if MSS_HEIGHT == 10 && !defined(MSS_CALC_RETAIN)
unsigned char pkey_test[NODE_VALUE_SIZE] =        {0xA6,0xC5,0xE5,0xE5,0xBB,0xEA,0x7F,0x31,0x5D,0x11,0x33,0x87,0x7A,0x95,0x45,0x74};
#else
unsigned char pkey_test[NODE_VALUE_SIZE];
#endif
unsigned char seed_test[LEN_BYTES(MSS_SEC_LVL)];
unsigned char h1[LEN_BYTES(WINTERNITZ_N)], h2[LEN_BYTES(WINTERNITZ_N)];
unsigned char sig_test[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];

int test_merkle_signature() {

	short errors, j;

	char M[] = "Hello, world!";

	// Set seed
	for (j = 0; j < LEN_BYTES(MSS_SEC_LVL); j++) {
		seed_test[j] = 0xA0 ^ j; // sample private key, for debugging only
	}
	sinit(&hash_mmo, MSS_SEC_LVL);
	DM_init(&f_test);

#if MSS_HEIGHT != 10 || (MSS_HEIGHT == 10 && defined(MSS_CALC_RETAIN))
	// Compute Merkle Public Key and TreeHash state
	mss_keygen(&f_test, &hash_mmo, seed_test, &nodes[0], &nodes[1], &state_test, pkey_test);
#endif

    print_retain(&state_test);

	//Sign and verify for all j-th authentication paths
	errors = 0;
	for (j = 0; j < (1 << MSS_HEIGHT); j++) {
#ifdef DEBUG
	    printf("Testing merkle signature for leaf %d ...", j);
#endif
	    mss_sign(&state_test, seed_test, &currentLeaf_test, (const char *)M, strlen(M)+1, &hash_mmo, &f_test, h1, j, &nodes[0], &nodes[1], sig_test, authpath_test);
        if(mss_verify(authpath_test, currentLeaf_test.value, (const char *)M, strlen(M)+1, &hash_mmo, &f_test, h2, j, sig_test, aux, &currentLeaf_test, pkey_test) == MSS_OK) {
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

