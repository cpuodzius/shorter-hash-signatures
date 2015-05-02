#include <stdio.h>
#include <string.h>
#include "test.h"
#include "mss.h"
//#include "aes_128.h"

#ifdef VERBOSE
	#include "util.h"
#endif

struct mss_node nodes[2];
struct mss_state state_test;
struct mss_node currentLeaf_test;
struct mss_node authpath_test[MSS_HEIGHT];
mmo_t hash1, hash2;
dm_t f_test;
#if defined(MSS_ROM_RETAIN)
	#if MSS_HEIGHT == 10
		unsigned char pkey_test[NODE_VALUE_SIZE] =	{0x86,0x29,0x44,0xFD,0xFE,0x51,0x59,0x1F,0xC1,0xFE,0x0E,0x4A,0x0A,0x9B,0xBD,0x39};
	#elif MSS_HEIGHT == 11
		unsigned char pkey_test[NODE_VALUE_SIZE] =	{0xe9,0xfc,0x31,0xfc,0xc6,0x77,0xcb,0x64,0x23,0x28,0x70,0xa7,0x4c,0x64,0xc0,0x76};
	#elif MSS_HEIGHT == 12
		unsigned char pkey_test[NODE_VALUE_SIZE] =	{0xd9,0xea,0x1a,0x5f,0x49,0xd5,0xb0,0x11,0x91,0x40,0x1b,0x4c,0xc3,0x18,0xed,0x62};
	#elif MSS_HEIGHT == 13
		unsigned char pkey_test[NODE_VALUE_SIZE] =	{0x49,0x69,0xed,0x13,0xe8,0x25,0x03,0x49,0x8c,0x27,0x9a,0x09,0x05,0xec,0xbe,0xe2};
	#elif MSS_HEIGHT == 14
		unsigned char pkey_test[NODE_VALUE_SIZE] =	{0x1e,0xd6,0xe7,0x7b,0x28,0x88,0xfa,0x2d,0x76,0xa9,0xa4,0x89,0x56,0xe8,0x94,0x8e};
	#elif MSS_HEIGHT == 15
		unsigned char pkey_test[NODE_VALUE_SIZE] =	{0x4f,0xa0,0x09,0x7f,0x4e,0xca,0xf4,0xa2,0x69,0x90,0x5f,0xe0,0x30,0xc5,0x01,0xb0};
	#elif MSS_HEIGHT == 16
		unsigned char pkey_test[NODE_VALUE_SIZE] =	{0xF3,0x3C,0x97,0x86,0xC8,0x05,0xB7,0x84,0x60,0x1D,0xA8,0x29,0x9A,0xC1,0x46,0x2C};		
	#endif
#else
	unsigned char pkey_test[NODE_VALUE_SIZE];
#endif
unsigned char seed_test[LEN_BYTES(MSS_SEC_LVL)] = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF};
unsigned char h1[LEN_BYTES(WINTERNITZ_N)], h2[LEN_BYTES(WINTERNITZ_N)];
unsigned char sig_test[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_N)];
unsigned char aux[LEN_BYTES(WINTERNITZ_N)];

unsigned short test_mss_signature() {

	unsigned short errors;
	unsigned long  j;

	char M[16] = " --Hello, world!";

	MMO_init(&hash1);
	MMO_init(&hash2);
	DM_init(&f_test);

	// Compute Merkle Public Key and TreeHash state
	mss_keygen_core(&hash1, &hash2, seed_test, &nodes[0], &nodes[1], &state_test, pkey_test);

#ifdef VERBOSE
	Display("Public Key", pkey_test, NODE_VALUE_SIZE);	
	#ifdef DEBUG
		print_retain(&state_test);
	#endif	
#endif	
	//printf("strlen %d\n",strlen(M));
	//Sign and verify for all j-th authentication paths
	errors = 0;
	for (j = 0; j < ((unsigned long)1 << MSS_HEIGHT); j++) {

#if defined(VERBOSE) && !defined(PLATFORM_SENSOR)
		printf("Testing MSS for leaf %ld ...", j);
#endif
		mss_sign_core(&state_test, seed_test, &currentLeaf_test, (const char *)M, strlen(M), &hash1, &hash2, h1, j, &nodes[0], &nodes[1], sig_test, authpath_test, pkey_test);
		//Display("",sig_test,16);
		if(mss_verify_core(authpath_test, (const char *)M, strlen(M), &hash1, &hash2, h2, j, sig_test, aux, &currentLeaf_test, pkey_test) == MSS_OK) {
#if defined(VERBOSE) && !defined(PLATFORM_SENSOR)
			printf(" [OK]\n");
#endif
		} else {
			errors++;
#if defined(VERBOSE) && !defined(PLATFORM_SENSOR)
			printf(" [ERROR]\n");
#endif
		}
	}

	return errors;
}

int test_AES128() {
	int errors;
	unsigned char cipher[AES_128_BLOCK_SIZE],
				  key[AES_128_BLOCK_SIZE] =  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
				              				  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
				  plain[AES_128_BLOCK_SIZE] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
							   				   0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	unsigned char expectedCipher[AES_128_BLOCK_SIZE] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 
													    0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};

	aes_128_encrypt(cipher, plain, key);

	errors = memcmp(cipher,expectedCipher,AES_128_BLOCK_SIZE);

#ifdef VERBOSE
	Display("cipher", cipher, AES_128_BLOCK_SIZE);	
#endif	

	return errors;
}

#ifdef SERIALIZATION

int test_mss_serialization() {
	unsigned short errors = 0;

	struct mss_node node_in, node_out;
	struct mss_state state_in, state_out;
	
	unsigned short index_in=0, index_out;
	unsigned char skey_in[LEN_BYTES(MSS_SEC_LVL)], skey_out[LEN_BYTES(MSS_SEC_LVL)];

	unsigned char ots_in[MSS_OTS_SIZE], ots_out[MSS_OTS_SIZE];
	struct mss_node authpath_in[MSS_HEIGHT], authpath_out[MSS_HEIGHT];

	// MSS NODE
	printf("Testing MSS Node serialization/deserialization ...");
	unsigned char buffer_node[MSS_NODE_SIZE];

	serialize_mss_node(node_in, buffer_node);
	deserialize_mss_node(&node_out, buffer_node);

	if(memcmp(&node_in, &node_out, sizeof(node_in)) == 0) {
		printf(" [OK]\n");
	} else {
		errors++;
		printf(" [ERROR]\n");
	}
	
	// MSS STATE
	printf("Testing MSS State serialization/deserialization...");
	unsigned char buffer_state[MSS_STATE_SIZE];

	serialize_mss_state(state_in, index_in, buffer_state);
	deserialize_mss_state(&state_out, &index_out, buffer_state);

	if((memcmp(&node_in, &node_out, sizeof(node_in)) == 0) && (index_in == index_out)) {
			printf(" [OK]\n");
	} else {
		errors++;
		printf(" [ERROR]\n");
	}
	
	// SKEY
	printf("Testing MSS skey serialization/deserialization...");
	unsigned char buffer_skey[MSS_SKEY_SIZE];

	serialize_mss_skey(state_in, index_in, skey_in, buffer_skey);
	deserialize_mss_skey(&state_out, &index_out, skey_out, buffer_skey);

	if((memcmp(&skey_in, &skey_out, sizeof(skey_in)) == 0) && (memcmp(&state_in, &state_out, sizeof(state_in)) == 0) && (index_in == index_out)) {
		printf(" [OK]\n");
	} else {
		errors++;
		printf(" [ERROR]\n");
	}
	
	// SIGNATURE
	printf("Testing MSS Signature serialization/deserialization...");
	unsigned char buffer_signature[MSS_SIGNATURE_SIZE];

	serialize_mss_signature(ots_in, node_in, authpath_in, buffer_signature);
	deserialize_mss_signature(ots_out, &node_out, authpath_out, buffer_signature);

	if((memcmp(&ots_in, &ots_out, sizeof(ots_in)) == 0) && (memcmp(&node_in, &node_out, sizeof(node_in)) == 0) && (memcmp(authpath_in, authpath_out, sizeof(authpath_in)) == 0)) {
		printf(" [OK]\n");
	} else {
		errors++;
		printf(" [ERROR]\n");
	}
	
	return errors;
}

#endif //test_mss_serialization

unsigned short do_test(enum TEST operation) {
	unsigned short errors = 0;

	switch(operation) {
		case TEST_MSS_SIGN:
			errors = test_mss_signature();
			break;
		case TEST_AES_ENC:
			errors = test_AES128();
			break;
#ifdef SERIALIZATION
		case TEST_MSS_SERIALIZATION:
			errors = test_mss_serialization();
			break;
#endif
		default:
			break;
	}
	printf("Errors: %d \n", errors);
	return errors;
}

#ifdef LIB_TEST

int main() {
	unsigned int test;
	for(test = 0; test < TEST_NTEST; test++)
		do_test(test);
	return 0;
}

#endif
