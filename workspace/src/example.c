/*
 * This function provides usage examples of the library
 */

#include <stdio.h>
#include <string.h>
#include "mss.h"
#include "util.h"

#define EXAMPLE_Nth_SIGNATURE	13
#define EXAMPLE_BASE64_BUFFER_SIZE	3000

int main() {
	printf("MSS library utilization example...\n");

	int i;
	char base64_buffer[EXAMPLE_BASE64_BUFFER_SIZE];
	unsigned char signature_serialization_buffer[EXAMPLE_BASE64_BUFFER_SIZE];

	/* Auxiliary varibles */
	struct mss_node node[3];
	unsigned char hash[LEN_BYTES(WINTERNITZ_N)];
	unsigned char ots[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
	unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];

	mmo_t hash_mmo;
	dm_t hash_dm;

	/* Merkle-tree variables */
	struct mss_state state;
	struct mss_node authpath[MSS_HEIGHT];

	unsigned char pkey[NODE_VALUE_SIZE];
	unsigned char skey[LEN_BYTES(MSS_SEC_LVL)] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F};

	printf("...variables declared\nInitializing hashes and merkle tree state...");

	/* Initialization of Merkle–Damgård hash */
	DM_init(&hash_dm);
	
	/* Initialization of Winternitz-MMO OTS */
	sinit(&hash_mmo, MSS_SEC_LVL);

	printf(" done!\nGenerating key...");

	mss_keygen_core(&hash_dm, &hash_mmo, skey, &node[0], &node[1], &state, pkey);

	printf(" done!\n");

	base64encode(skey, LEN_BYTES(WINTERNITZ_N), base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("skey: %s\n", base64_buffer);
	base64encode(pkey, LEN_BYTES(WINTERNITZ_N), base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("pkey: %s\n", base64_buffer);


	const char M[] = "Long Johnson, Don Piano";
	base64encode(M, strlen(M), base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("message: %s\n", base64_buffer);
	printf("Signing message (obtaining %d OTS)...", EXAMPLE_Nth_SIGNATURE);

	for(i = 0; i < EXAMPLE_Nth_SIGNATURE; i++)
		mss_sign_core(&state, skey, &node[0], M, strlen(M) + 1, &hash_mmo, &hash_dm, hash, i, &node[1], &node[2], ots, authpath);
	i--;

	printf(" done!\n");

	serialize_signature(ots, node[0], authpath, signature_serialization_buffer);
	base64encode(signature_serialization_buffer, MSS_SIGNATURE_SIZE, base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("sig: %s\n", base64_buffer);

	printf("Verifying signature...");

	mss_verify_core(authpath, node[0].value, M, strlen(M) + 1, &hash_mmo, &hash_dm, hash, i, ots, aux, &node[0], pkey);

	printf(" done!\n");

	return 0;
}

