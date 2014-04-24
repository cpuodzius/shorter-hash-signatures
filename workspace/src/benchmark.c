#include "benchmark.h"
#include "mss.h"

#ifdef PLATFORM_TELOSB
#include "sponge.h"
#include "sponge.c"
#include "winternitz.c"
#include "mss.c"
#include "mmo.c"
#endif


unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], seedPos[LEN_BYTES(MSS_SEC_LVL)];
unsigned char pkey[NODE_VALUE_SIZE];
//unsigned char IV[16];
struct mss_node nodes[2];
struct state_mt state;
sponge_t sponges[3];

//Merkle sign and verify
char M[] = "Hello, world!";
unsigned char h1[LEN_BYTES(WINTERNITZ_SEC_LVL)],h2[LEN_BYTES(WINTERNITZ_SEC_LVL)];
short pos = 0;
struct mss_node currentLeaf;
struct mss_node authpath[MSS_HEIGHT];
unsigned char sig[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];


void do_benchmark(enum BENCHMARK phase) {
	short j;

	switch(phase) {
		case BENCHMARK_PREPARE:
			for (j = 0; j < LEN_BYTES(MSS_SEC_LVL); j++) {
				seed[j] = 0xA0 ^ j; // sample private key, for debugging only
			}
            //memset(IV, 0, 16);

			sinit(&sponges[0], MSS_SEC_LVL);
			sinit(&sponges[1], MSS_SEC_LVL);
			sinit(&sponges[2], MSS_SEC_LVL);
			davies_meyer_init(&sponges[0]);
			mss_keygen(&sponges[0] , &sponges[1], &sponges[2], seed, &nodes[0], &nodes[1], &state, pkey);
			break;
		case BENCHMARK_MSS_KEYGEN:
			mss_keygen(&sponges[0] , &sponges[1], &sponges[2], seed, &nodes[0], &nodes[1], &state, pkey);
			break;
		case BENCHMARK_MSS_SIGN:
			for(j = 0; j < (1 << MSS_HEIGHT); j++) {
			    create_leaf(&sponges[0],&sponges[1],&sponges[2],&currentLeaf,j,seed);
			    mss_sign(&state, seed, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h1, j, &nodes[0], &nodes[1], sig, authpath);
			}
			break;
		case BENCHMARK_MSS_VERIFY:
		    mss_verify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h2, pos, sig, aux, &currentLeaf, pkey);
			break;
		case BENCHMARK_WINTERNITZ_KEYGEN:
			winternitz_keygen(nodes[0].value, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], nodes[1].value);
			break;
		case BENCHMARK_HASH_CALC:
#if HASH == BLAKE2S
			//blake2s_init(&sponges[0], LEN_BYTES(WINTERNITZ_SEC_LVL));
			//blake2s_update(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
			//blake2s_final(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
#elif HASH == MMO
			MMO_init(&sponges[0]);
			MMO_update(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
			MMO_final(&sponges[0], seed);
#endif

			break;
	}
}

