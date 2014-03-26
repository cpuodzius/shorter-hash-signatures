#include "benchmark.h"
#include "merkletree.h"

unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)];
unsigned char pkey[NODE_VALUE_SIZE];
struct node_t nodes[2];
struct state_mt state;
sponge_t sponges[3];

void do_benchmark(enum BENCHMARK phase) {
	short j;

	switch(phase) {
		case BENCHMARK_PREPARE:
			for (j = 0; j < LEN_BYTES(MERKLE_TREE_SEC_LVL); j++) {
				seed[j] = 0xA0 ^ j; // sample private key, for debugging only
			}
			sinit(&sponges[0], MERKLE_TREE_SEC_LVL);
			sinit(&sponges[1], MERKLE_TREE_SEC_LVL);
			sinit(&sponges[2], MERKLE_TREE_SEC_LVL);
			break;
		case BENCHMARK_KEYGEN:
			mt_keygen(&sponges[0] , &sponges[1], &sponges[2], seed, &nodes[0], &nodes[1], &state, pkey);
			break;
		case BENCHMARK_SIGN:
			break;
		case BENCHMARK_VERIFY:
			break;
		case BENCHMARK_WINTERNITZ_KEYGEN:
			winternitzGen(nodes[0].value, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], nodes[1].value);
			break;
		case BENCHMARK_HASH_CALC:
			blake2s_init(&sponges[0], LEN_BYTES(WINTERNITZ_SEC_LVL));
			blake2s_update(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
			blake2s_final(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
			break;
	}
}

