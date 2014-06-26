//#include <stdio.h>
//#include <stdint.h>
#include "benchmark.h"
#include <string.h>

#ifdef PLATFORM_TELOSB
#include "sponge.h"
#include "sponge.c"
#include "winternitz.c"
#include "mss.c"
#include "mmo.c"
#endif

//Merkle sign and verify aux variables

unsigned char seed_bench[LEN_BYTES(MSS_SEC_LVL)] = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF};
#if MSS_HEIGHT == 10
unsigned char pkey_bench[NODE_VALUE_SIZE] =        {0xA6,0xC5,0xE5,0xE5,0xBB,0xEA,0x7F,0x31,0x5D,0x11,0x33,0x87,0x7A,0x95,0x45,0x74};
#else
unsigned char pkey_bench[NODE_VALUE_SIZE];
#endif
struct mss_node nodes[2];
struct mss_node currentLeaf_bench;
struct mss_node authpath_bench[MSS_HEIGHT];
struct state_mt state_bench;
mmo_t hash_mmo;
dm_t f_bench;
char M_bench[] = "Hello, world!";
unsigned char h1[LEN_BYTES(WINTERNITZ_N)];
short j_bench;
unsigned char sig_bench[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];

// AES Calc variables
#ifdef AES_ASM
/*
aes128_ctx_t ctx; // the context where the round keys are stored
unsigned char ciphertext_bench[16];
unsigned char plaintext_bench[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
			  	     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
unsigned char key_bench[16] =  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
				0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
//*/
#endif

void do_benchmark(enum BENCHMARK phase, short benchs) {
	switch(phase) {
		case BENCHMARK_PREPARE:
			sinit(&hash_mmo, MSS_SEC_LVL);
			DM_init(&f_bench);
			mss_keygen(&f_bench, &hash_mmo, seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);
			break;
		case BENCHMARK_MSS_KEYGEN:
			mss_keygen(&f_bench, &hash_mmo, seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);
			//print_retain(&state_bench);
			//printfflush();
			break;
		case BENCHMARK_MSS_SIGN:
			for(j_bench = 0; j_bench < (1 << MSS_HEIGHT); j_bench++) {
			    mss_sign(&state_bench, seed_bench, &currentLeaf_bench, M_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &hash_mmo, &f_bench, h1, j_bench, &nodes[0], &nodes[1], sig_bench, authpath_bench);
			}
			break;
		case BENCHMARK_MSS_PREPARE_VERIFY:
			sinit(&hash_mmo, MSS_SEC_LVL);
			DM_init(&f_bench);

			mss_keygen(&f_bench, &hash_mmo, seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);

			mss_sign(&state_bench, seed_bench, &currentLeaf_bench, M_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &hash_mmo, &f_bench, h1, 0, &nodes[0],
				 &nodes[1], sig_bench, authpath_bench);
		case BENCHMARK_MSS_VERIFY:
		    for(j_bench = 0; j_bench < benchs; j_bench++) {
		        mss_verify(authpath_bench, currentLeaf_bench.value, M_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &hash_mmo, &f_bench, h1, 0, sig_bench, aux,
				   &currentLeaf_bench, pkey_bench);
		    }
			break;
		case BENCHMARK_WINTERNITZ_KEYGEN:
			DM_init(&f_bench);
			winternitz_keygen(seed_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &hash_mmo, &f_bench, nodes[1].value);
			break;
		case BENCHMARK_WINTERNITZ_SIGN:
			winternitz_sign(seed_bench, nodes[1].value, LEN_BYTES(WINTERNITZ_SEC_LVL), M_bench, strlen(M_bench)+1, &hash_mmo, &f_bench, h1, sig_bench);
			break;
		case BENCHMARK_WINTERNITZ_VERIFY:
			winternitz_verify(nodes[1].value, LEN_BYTES(WINTERNITZ_SEC_LVL), M_bench, strlen(M_bench)+1, &hash_mmo, &f_bench, h1, sig_bench, aux);
			break;
		case BENCHMARK_HASH_CALC:
			for(j_bench = 0; j_bench < benchs; j_bench++) {
				//*
				sinit(&hash_mmo, WINTERNITZ_SEC_LVL);
				absorb(&hash_mmo, seed_bench, LEN_BYTES(WINTERNITZ_SEC_LVL));
				squeeze(&hash_mmo, seed_bench, LEN_BYTES(WINTERNITZ_SEC_LVL));
				//*/
				//hash16(&f_bench,seed_bench,seed_bench);
			}
			break;
		case BENCHMARK_AES_CALC:
			 //Expected ciphertext
			//res[0] = 0x39; res[1] = 0x25; res[2] = 0x84; res[3] = 0x1d;
			//res[4] = 0x02; res[5] = 0xdc; res[6] = 0x09; res[7] = 0xfb;
			//res[8] = 0xdc; res[9] = 0x11; res[10] = 0x85; res[11] = 0x97;
			//res[12] = 0x19; res[13] = 0x6a; res[14] = 0x0b; res[15] = 0x32;

			//memcpy(local_key,key_bench,16);
			//Display("key", key_bench, 16);
			//Display("plain", plaintext_bench, 16);

			//for(j_bench = 0; j_bench < benchs; j_bench++) {
			//	AES_encrypt(ciphertext_bench, plaintext_bench, key_bench);
			//}

			//Display("key", key_bench, 16);
			//Display("plain", plaintext_bench, 16);
			//Display("cipher", ciphertext_bench, 16);

			//printfflush();

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

