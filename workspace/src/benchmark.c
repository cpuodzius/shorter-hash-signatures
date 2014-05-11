#include <stdio.h>
#include "benchmark.h"

#ifdef PLATFORM_TELOSB
#include "sponge.h"
#include "sponge.c"
#include "winternitz.c"
#include "mss.c"
#include "mmo.c"
#endif

//Merkle sign and verify aux variables

unsigned char seed[LEN_BYTES(MSS_SEC_LVL)];
unsigned char pkey[NODE_VALUE_SIZE];
struct mss_node nodes[2];
struct mss_node currentLeaf;
struct mss_node authpath[MSS_HEIGHT];
struct state_mt state;
sponge_t sponges[2];

char M[] = "Hello, world!";
unsigned char h1[LEN_BYTES(WINTERNITZ_SEC_LVL)];
short j;
unsigned char sig[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];


void do_benchmark(enum BENCHMARK phase) {
	
	switch(phase) {
		case BENCHMARK_PREPARE:
			for (j = 0; j < LEN_BYTES(MSS_SEC_LVL); j++) {
				seed[j] = 0xA0 ^ j; // sample private key, for debugging only
			}
			sinit(&sponges[0], MSS_SEC_LVL);
			sinit(&sponges[1], MSS_SEC_LVL);

			mss_keygen(&sponges[0] , &sponges[1], seed, &nodes[0], &nodes[1], &state, pkey);
			break;
		case BENCHMARK_MSS_KEYGEN:
			mss_keygen(&sponges[0] , &sponges[1], seed, &nodes[0], &nodes[1], &state, pkey);
			break;
		case BENCHMARK_MSS_SIGN:
			for(j = 0; j < (1 << MSS_HEIGHT); j++) {
			    mss_sign(&state, seed, &currentLeaf, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], h1, j, &nodes[0], &nodes[1], sig, authpath);
			}
			break;
		case BENCHMARK_MSS_PREPARE_VERIFY:
			for (j = 0; j < LEN_BYTES(MSS_SEC_LVL); j++) {
				seed[j] = 0xA0 ^ j; // sample private key, for debugging only
			}
			sinit(&sponges[0], MSS_SEC_LVL);
			sinit(&sponges[1], MSS_SEC_LVL);

			mss_keygen(&sponges[0], &sponges[1], seed, &nodes[0], &nodes[1], &state, pkey);
			mss_sign(&state, seed, &currentLeaf, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], h1, 0, &nodes[0],
				 &nodes[1], sig, authpath);
		case BENCHMARK_MSS_VERIFY:
		        mss_verify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], h1, 0, sig, aux,
				   &currentLeaf, pkey);
			break;
		case BENCHMARK_WINTERNITZ_KEYGEN:
			winternitz_keygen(seed, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], nodes[1].value);
			break;
		case BENCHMARK_WINTERNITZ_SIGN:
			winternitz_sign(seed, nodes[1].value, LEN_BYTES(WINTERNITZ_SEC_LVL), M, strlen(M)+1, &sponges[0], h1, sig);
			break;
		case BENCHMARK_WINTERNITZ_VERIFY:
			winternitz_verify(nodes[1].value, LEN_BYTES(WINTERNITZ_SEC_LVL), M, strlen(M)+1, &sponges[0], &sponges[1], h1, sig, aux);
			break;
		case BENCHMARK_HASH_CALC:
			sinit(&sponges[0], WINTERNITZ_SEC_LVL);
			absorb(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
			squeeze(&sponges[0], seed, LEN_BYTES(WINTERNITZ_SEC_LVL));
			break;
	}
}

#ifdef BENCH_SELFTEST

    #include <time.h>
    #include "util.h"

    int main(int argc, char *argv[]) {
        int mark = 1000;
        clock_t elapsed;

        printf("\n Parameters:  SEC_LVL=%u, H=%u, K=%u, W=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W);

        do_benchmark(BENCHMARK_PREPARE);

        elapsed = -clock();
        for(int i = 0; i < mark; i++) {
            //do_benchmark(BENCHMARK_MSS_KEYGEN);
            do_benchmark(BENCHMARK_MSS_SIGN);
            //do_benchmark(BENCHMARK_MSS_PREPARE_VERIFY);
            //do_benchmark(BENCHMARK_MSS_VERIFY);
            //do_benchmark(BENCHMARK_WINTERNITZ_KEYGEN);
            //do_benchmark(BENCHMARK_WINTERNITZ_SIGN);
            //do_benchmark(BENCHMARK_WINTERNITZ_VERIFY);
            //do_benchmark(BENCHMARK_HASH_CALC);
        }

        elapsed += clock();
        printf("Elapsed time: %.1f ms\n", 1000*(float)elapsed/CLOCKS_PER_SEC/mark);
    }
#endif

