//#include <stdio.h>
#include "benchmark.h"
//#include <string.h>

#ifdef PLATFORM_TELOSB
#include "sponge.h"
#include "sponge.c"
#include "winternitz.c"
#include "mss.c"
#include "mmo.c"
#endif

//Merkle sign and verify aux variables

unsigned char seed_bench[LEN_BYTES(MSS_SEC_LVL)];
unsigned char pkey_bench[NODE_VALUE_SIZE];
struct mss_node nodes[2];
struct mss_node currentLeaf_bench;
struct mss_node authpath_bench[MSS_HEIGHT];
struct state_mt state_bench;
sponge_t sponges[2];
dm_t f_bench;
char M_bench[] = "Hello, world!";
unsigned char h1[LEN_BYTES(WINTERNITZ_SEC_LVL)];
short j_bench;
unsigned char sig_bench[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];

void _start_seed(unsigned char seed[LEN_BYTES(MSS_SEC_LVL)]) {
    for (j_bench = 0; j_bench < LEN_BYTES(MSS_SEC_LVL); j_bench++) {
        seed[j_bench] = 0xA0 ^ j_bench; // sample private key, for debugging only
    }
}

void do_benchmark(enum BENCHMARK phase, short benchs) {

	switch(phase) {
		case BENCHMARK_PREPARE:
            _start_seed(seed_bench);
			sinit(&sponges[0], MSS_SEC_LVL);
			sinit(&sponges[1], MSS_SEC_LVL);
			DM_init(&f_bench);

			mss_keygen(&f_bench, &sponges[1], seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);

			break;
		case BENCHMARK_MSS_KEYGEN:
			mss_keygen(&f_bench, &sponges[1], seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);
			break;
		case BENCHMARK_MSS_SIGN:
			for(j_bench = 0; j_bench < (1 << MSS_HEIGHT); j_bench++) {
			    mss_sign(&state_bench, seed_bench, &currentLeaf_bench, M_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &f_bench, h1, j_bench, &nodes[0], &nodes[1], sig_bench, authpath_bench);
			}
			break;
		case BENCHMARK_MSS_PREPARE_VERIFY:
			_start_seed(seed_bench);
			sinit(&sponges[0], MSS_SEC_LVL);
			sinit(&sponges[1], MSS_SEC_LVL);
			DM_init(&f_bench);

			mss_keygen(&f_bench, &sponges[1], seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);

			mss_sign(&state_bench, seed_bench, &currentLeaf_bench, M_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &f_bench, h1, 0, &nodes[0],
				 &nodes[1], sig_bench, authpath_bench);
		case BENCHMARK_MSS_VERIFY:
		    for(j_bench = 0; j_bench < (1 << MSS_HEIGHT); j_bench++) {
		        mss_verify(authpath_bench, currentLeaf_bench.value, M_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &f_bench, h1, 0, sig_bench, aux,
				   &currentLeaf_bench, pkey_bench);
		    }
			break;
		case BENCHMARK_WINTERNITZ_KEYGEN:
			DM_init(&f_bench);
			_start_seed(seed_bench);
			winternitz_keygen(seed_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[1], &f_bench, nodes[1].value);
			break;
		case BENCHMARK_WINTERNITZ_SIGN:
			winternitz_sign(seed_bench, nodes[1].value, LEN_BYTES(WINTERNITZ_SEC_LVL), M_bench, strlen(M_bench)+1, &sponges[0], &f_bench, h1, sig_bench);
			break;
		case BENCHMARK_WINTERNITZ_VERIFY:
			winternitz_verify(nodes[1].value, LEN_BYTES(WINTERNITZ_SEC_LVL), M_bench, strlen(M_bench)+1, &sponges[0], &sponges[1], &f_bench, h1, sig_bench, aux);
			break;
		case BENCHMARK_HASH_CALC:
			_start_seed(seed_bench);
			for(j_bench = 0; j_bench < benchs; j_bench++) {
				//* //MMO
				sinit(&sponges[0], WINTERNITZ_SEC_LVL);
				absorb(&sponges[0], seed_bench, LEN_BYTES(WINTERNITZ_SEC_LVL));
				squeeze(&sponges[0], seed_bench, LEN_BYTES(WINTERNITZ_SEC_LVL));
				//*/			
				//hash16(&f_bench,seed_bench,seed_bench);
			}
			break;
		case BENCHMARK_AES_CALC:
			_start_seed(seed_bench);
			for(j_bench = 0; j_bench < benchs; j_bench++) {
				AES_encrypt(aux, seed_bench, aux); // aux <= AES_seed(aux)

			}
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
            //do_benchmark(BENCHMARK_MSS_KEYGEN, mark);
            do_benchmark(BENCHMARK_MSS_SIGN, mark);
            //do_benchmark(BENCHMARK_MSS_PREPARE_VERIFY, mark);
            //do_benchmark(BENCHMARK_MSS_VERIFY, mark);
            //do_benchmark(BENCHMARK_WINTERNITZ_KEYGEN, mark);
            //do_benchmark(BENCHMARK_WINTERNITZ_SIGN, mark);
            //do_benchmark(BENCHMARK_WINTERNITZ_VERIFY, mark);
            //do_benchmark(BENCHMARK_HASH_CALC, mark);
        }

        elapsed += clock();
        printf("Elapsed time: %.1f ms\n", 1000*(float)elapsed/CLOCKS_PER_SEC/mark);
    }
#endif

