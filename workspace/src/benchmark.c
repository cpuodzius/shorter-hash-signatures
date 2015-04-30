//#include <stdio.h>
//#include <stdint.h>
#include <string.h>
#include "benchmark.h"
#include "hash.h"

//Merkle sign and verify aux variables

unsigned char seed_bench[LEN_BYTES(MSS_SEC_LVL)] = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF};

#if   MSS_HEIGHT == 10
unsigned char pkey_bench[NODE_VALUE_SIZE] =        {0xA6,0xC5,0xE5,0xE5,0xBB,0xEA,0x7F,0x31,0x5D,0x11,0x33,0x87,0x7A,0x95,0x45,0x74};
#elif MSS_HEIGHT == 11
unsigned char pkey_bench[NODE_VALUE_SIZE] =        {0xe9,0xfc,0x31,0xfc,0xc6,0x77,0xcb,0x64,0x23,0x28,0x70,0xa7,0x4c,0x64,0xc0,0x76};
#elif MSS_HEIGHT == 12
unsigned char pkey_bench[NODE_VALUE_SIZE] =        {0xd9,0xea,0x1a,0x5f,0x49,0xd5,0xb0,0x11,0x91,0x40,0x1b,0x4c,0xc3,0x18,0xed,0x62};
#elif MSS_HEIGHT == 13
unsigned char pkey_bench[NODE_VALUE_SIZE] =        {0x49,0x69,0xed,0x13,0xe8,0x25,0x03,0x49,0x8c,0x27,0x9a,0x09,0x05,0xec,0xbe,0xe2};
#elif MSS_HEIGHT == 14
unsigned char pkey_bench[NODE_VALUE_SIZE] =        {0x1e,0xd6,0xe7,0x7b,0x28,0x88,0xfa,0x2d,0x76,0xa9,0xa4,0x89,0x56,0xe8,0x94,0x8e};
#elif MSS_HEIGHT == 15                             
unsigned char pkey_bench[NODE_VALUE_SIZE] =        {0x4f,0xa0,0x09,0x7f,0x4e,0xca,0xf4,0xa2,0x69,0x90,0x5f,0xe0,0x30,0xc5,0x01,0xb0};
#elif MSS_HEIGHT == 16
unsigned char pkey_bench[NODE_VALUE_SIZE] =	   	   {0xF3,0x3C,0x97,0x86,0xC8,0x05,0xB7,0x84,0x60,0x1D,0xA8,0x29,0x9A,0xC1,0x46,0x2C};		
#else
unsigned char pkey_bench[NODE_VALUE_SIZE];
#endif

struct mss_node nodes[2];
struct mss_node currentLeaf_bench;
struct mss_node authpath_bench[MSS_HEIGHT];
struct mss_state state_bench;
mmo_t hash_mmo;
dm_t f_bench;
char M_bench[16] = " --Hello, world!";
unsigned char h1[LEN_BYTES(WINTERNITZ_N)], h2[LEN_BYTES(WINTERNITZ_N)];
unsigned char sig_bench[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
unsigned char aux[LEN_BYTES(WINTERNITZ_N)];

void do_benchmark(enum BENCHMARK phase, unsigned short benchs) {
	unsigned long j;

	unsigned char cipher[AES_128_BLOCK_SIZE],
			  key[AES_128_BLOCK_SIZE] =  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			              				  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
			  plain[AES_128_BLOCK_SIZE] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
						   				   0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};	

	switch(phase) {

		case BENCHMARK_PREPARE:

			DM_init(&f_bench);
			mss_keygen_core(&f_bench, &hash_mmo, seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);
			break;

		case BENCHMARK_MSS_KEYGEN:

			mss_keygen_core(&f_bench, &hash_mmo, seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);
#ifdef VERBOSE
			//print_retain(&state_bench);
			//printfflush();			
			Display("Public Key", pkey_bench, NODE_VALUE_SIZE);
#endif				
			break;

		case BENCHMARK_MSS_SIGN:
			for(j = 0; j < ((unsigned long)1 << MSS_HEIGHT); j++) {
			//for(j = 0; j < (1 << 10); j++) { //pt1 0..2^10-1
			//for(j = (1 << 10); j < (1 << 11); j++) { //pt2 2^10..2^11-1
			//for(j = 0; j < (1 << (MSS_HEIGHT-2)); j++) { //pt1 0..2^11-1
			//for(j = (1 << (MSS_HEIGHT-2)); j < (1 << (MSS_HEIGHT-1)); j++) { //pt2 2^11...2^12-1
			//for(j = (1 << (MSS_HEIGHT-1)); j < (1 << (MSS_HEIGHT-1)) + 2048; j++) { //pt3 2^12...2^12+2048-1
			//for(j = (1 << (MSS_HEIGHT-1)) + 2048; j < (1 << MSS_HEIGHT); j++) { //pt4 2^12+2048...2^13-1
				mss_sign_core(&state_bench, seed_bench, &currentLeaf_bench, M_bench, LEN_BYTES(WINTERNITZ_SEC_LVL), &hash_mmo, &f_bench, h1, j, &nodes[0], &nodes[1], sig_bench, authpath_bench, pkey_bench);			    
			}
			break;

		case BENCHMARK_MSS_PREPARE_VERIFY:

			MMO_init(&hash_mmo);
			DM_init(&f_bench);
			//mss_keygen(&f_bench, &hash_mmo, seed_bench, &nodes[0], &nodes[1], &state_bench, pkey_bench);		
			mss_sign_core(&state_bench, seed_bench, &currentLeaf_bench, M_bench, strlen(M_bench)+1, &hash_mmo, &f_bench, h1, 0, &nodes[0],
				 &nodes[1], sig_bench, authpath_bench,pkey_bench);
			DM_hash16(&f_bench,(unsigned char*)M_bench,h2);// put a "random-looking" value on h2 
			break;

		case BENCHMARK_MSS_VERIFY:
			for(j = 0; j < benchs; j++) {
				mss_verify_core(authpath_bench, M_bench, LEN_BYTES(WINTERNITZ_N), &hash_mmo, &f_bench, h2, 0, sig_bench, aux, &currentLeaf_bench, pkey_bench);
			}
			break;

		case BENCHMARK_WINTERNITZ_KEYGEN:
			winternitz_keygen(seed_bench, &hash_mmo, &f_bench, nodes[1].value);
			break;

		case BENCHMARK_WINTERNITZ_SIGN:
			MMO_init(&hash_mmo);
			MMO_update(&hash_mmo,(unsigned char *)M_bench,16);
			MMO_final(&hash_mmo,h1);
			winternitz_sign(seed_bench, &hash_mmo, &f_bench, h1, sig_bench);
			break;

		case BENCHMARK_WINTERNITZ_VERIFY:
			MMO_init(&hash_mmo);
			MMO_update(&hash_mmo,(unsigned char *)M_bench,16);
			MMO_final(&hash_mmo,h2);
			winternitz_verify(nodes[1].value, &hash_mmo, &f_bench, h2, sig_bench, aux);
			break;

		case BENCHMARK_HASH16_CALC:

			for(j = 0; j < benchs; j++) {
				DM_hash16(&f_bench,seed_bench,seed_bench);
				//MMO_hash16(&f_bench,seed_bench,seed_bench);
			}

			break;
		case BENCHMARK_HASH_CALC:

			for(j = 0; j < benchs; j++) {
				MMO_init(&hash_mmo);
				MMO_update(&hash_mmo, seed_bench, LEN_BYTES(WINTERNITZ_SEC_LVL));
				MMO_final(&hash_mmo, seed_bench);
			}

			break;			

		case BENCHMARK_AES_ENC:

			for(j = 0; j < benchs; j++) {
				aes_128_encrypt(cipher, plain, key);
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
            //do_benchmark(BENCHMARK_AES_ENC, mark);

        }

        elapsed += clock();

        printf("Elapsed time: %.1f ms\n", 1000*(float)elapsed/CLOCKS_PER_SEC/mark);
    }
#endif
