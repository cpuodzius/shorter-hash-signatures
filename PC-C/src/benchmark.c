#include "benchmark.h"
#include "merkletree.h"

#ifdef PLATFORM_TELOSB
#include "sponge.h"
#include "sponge.c"
#include "winternitz.c"
#include "merkle_tree.c"
#include "mmo.c"
#endif


unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], seedPos[LEN_BYTES(MERKLE_TREE_SEC_LVL)];
unsigned char pkey[NODE_VALUE_SIZE];
//unsigned char IV[16];
struct node_t nodes[2];
struct state_mt state;
sponge_t sponges[3];

//Merkle sign and verify
char M[] = "Hello, world!";
unsigned char h1[LEN_BYTES(WINTERNITZ_SEC_LVL)],h2[LEN_BYTES(WINTERNITZ_SEC_LVL)];
short pos = 0;
struct node_t currentLeaf;
struct node_t authpath[MERKLE_TREE_HEIGHT];
unsigned char sig[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];


void do_benchmark(enum BENCHMARK phase) {
	short j;

	switch(phase) {
		case BENCHMARK_PREPARE:
			for (j = 0; j < LEN_BYTES(MERKLE_TREE_SEC_LVL); j++) {
				seed[j] = 0xA0 ^ j; // sample private key, for debugging only
			}
            //memset(IV, 0, 16);

			sinit(&sponges[0], MERKLE_TREE_SEC_LVL);
			sinit(&sponges[1], MERKLE_TREE_SEC_LVL);
			sinit(&sponges[2], MERKLE_TREE_SEC_LVL);
			davies_meyer_init(&sponges[0]);
			mt_keygen(&sponges[0] , &sponges[1], &sponges[2], seed, &nodes[0], &nodes[1], &state, pkey);
			break;
		case BENCHMARK_KEYGEN:
			mt_keygen(&sponges[0] , &sponges[1], &sponges[2], seed, &nodes[0], &nodes[1], &state, pkey);
			break;
		case BENCHMARK_SIGN:
			for(j = 0; j < (1 << MERKLE_TREE_HEIGHT); j++) {
			    create_leaf(&sponges[0],&sponges[1],&sponges[2],&currentLeaf,j,seed);
			    merkletreeSign(&state, seed, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h1, j, &nodes[0], &nodes[1], sig, authpath);
			}
			break;
		case BENCHMARK_VERIFY:
		    merkletreeVerify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h2, pos, sig, aux, &currentLeaf, pkey);
			break;
		case BENCHMARK_WINTERNITZ_KEYGEN:
			winternitzGen(nodes[0].value, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], nodes[1].value);
			break;
		case BENCHMARK_HASH_CALC:
#ifdef USE_BLAKE2S
			blake2s_init(&sponges[0], LEN_BYTES(WINTERNITZ_SEC_LVL));
			blake2s_update(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
			blake2s_final(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
#endif
			break;
	}
}

