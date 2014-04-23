#include <stdio.h>
#include "test.h"
#include "merkletree.h"

#ifdef PLATFORM_TELOSB
#include "sponge.h"
#include "sponge.c"
#include "winternitz.c"
#include "merkle_tree.c"
#include "mmo.c"
#endif


int test_merkle_signature() {

	struct node_t nodes[2];
	struct state_mt state;
	struct node_t currentLeaf;
	struct node_t authpath[MERKLE_TREE_HEIGHT];
	sponge_t sponges[3];
	unsigned char pkey[NODE_VALUE_SIZE];
	unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)];
	unsigned char h1[LEN_BYTES(WINTERNITZ_SEC_LVL)], h2[LEN_BYTES(WINTERNITZ_SEC_LVL)];
	unsigned char sig[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
	unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];
	short errors, j;
	char M[] = "Hello, world!";

	printf("Testing merkle, w=%d, H=%d, K=%d\n\n", WINTERNITZ_W, MERKLE_TREE_HEIGHT, MERKLE_TREE_K);

    davies_meyer_init(&sponges[0]);

	// Set seed
	for (j = 0; j < LEN_BYTES(MERKLE_TREE_SEC_LVL); j++) {
		seed[j] = 0xA0 ^ j; // sample private key, for debugging only
	}
	sinit(&sponges[0], MERKLE_TREE_SEC_LVL);
	sinit(&sponges[1], MERKLE_TREE_SEC_LVL);
	sinit(&sponges[2], MERKLE_TREE_SEC_LVL);

	// Compute Merkle Public Key
	mt_keygen(&sponges[0] , &sponges[1], &sponges[2], seed, &nodes[0], &nodes[1], &state, pkey);

	//Sign and verify for all j-th authentication paths

	errors = 0;
	for(j = 0; j < (1 << MERKLE_TREE_HEIGHT); j++) {
	    printf("Testing auth path %d ...", j);
	    create_leaf(&sponges[0],&sponges[1],&sponges[2],&currentLeaf,j,seed);
	    merkletreeSign(&state, seed, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h1, j, &nodes[0], &nodes[1], sig, authpath);
        if(merkletreeVerify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h2, j, sig, aux, &currentLeaf, pkey) != 1) {
	    	errors++;
            printf(" [ERROR]\n");
	    } else {
            printf(" [OK]\n");
	    }
	}

	return errors;
}

int do_test(enum TEST operation) {
	unsigned char ret;

	switch(operation) {
		case TEST_MERKLE_SIGN:
			ret = test_merkle_signature();
            printf("Errors: %d \n", ret);
			break;
	}
	return ret;
}

