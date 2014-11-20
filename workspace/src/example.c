/*
 * This function provides usage examples of the library
 */

#include <stdio.h>
#include <string.h>
#include "mss.h"
#include "util.h"

#define EXAMPLE_Nth_SIGNATURE		13
#define EXAMPLE_BASE64_BUFFER_SIZE	3000

int main() {
	printf("MSS library utilization example...\n\n");
	printf("*****************************************\n");
	printf("*                                       *\n");
	printf("*          MSS Core Functions           *\n");
	printf("*                                       *\n");
	printf("*****************************************\n");

	int i;
	char base64_buffer[EXAMPLE_BASE64_BUFFER_SIZE];
	unsigned char signature_serialization_buffer[EXAMPLE_BASE64_BUFFER_SIZE];

	/* Auxiliary varibles */
	struct mss_node node[3];
	unsigned char hash[LEN_BYTES(WINTERNITZ_N)];
	unsigned char ots[MSS_OTS_SIZE];
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
	//DM_init(&hash_dm);
	
	/* Initialization of Winternitz-MMO OTS */
	//DM_init(&hash_mmo, MSS_SEC_LVL);

	printf(" done!\nGenerating key...");

	mss_keygen_core(&hash_dm, &hash_mmo, skey, &node[0], &node[1], &state, pkey);

	printf(" done!\n\n");

	base64encode(skey, LEN_BYTES(WINTERNITZ_N), base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("*****************************************\n");
	printf("skey: %s\n", base64_buffer);
	base64encode(pkey, LEN_BYTES(WINTERNITZ_N), base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("pkey: %s\n", base64_buffer);
	printf("*****************************************\n");


	const char message[] = "Long Johnson, Don Piano";
	base64encode(message, strlen(message), base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("\n*****************************************\n");
	printf("message: %s\n", base64_buffer);

	printf("Signing message (obtaining %d OTS)...", EXAMPLE_Nth_SIGNATURE);
	for(i = 0; i < EXAMPLE_Nth_SIGNATURE; i++)
		mss_sign_core(&state, skey, &node[0], (const char*)message, strlen(message) + 1, &hash_mmo, &hash_dm, hash, i, &node[1], &node[2], ots, authpath);

	printf(" done!\n");
	printf("*****************************************\n");

	serialize_mss_signature(ots, node[0], authpath, signature_serialization_buffer);

	base64encode(signature_serialization_buffer, MSS_SIGNATURE_SIZE, base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("Signature: %s\n", base64_buffer);

	/*
	printf("*****************************************\n");
	printf("pkey\n%d\n", NODE_VALUE_SIZE);
	for(i=0; i < NODE_VALUE_SIZE; i++)
		printf("%02X", pkey[i]);
	printf("\n*****************************************\n");
	printf("message\n%d\n", strlen(message));
	for(i=0; i< strlen(message); i++)
		printf("%02X", message[i]);
	printf("\n*****************************************\n");
	printf("signature\n%d\n", MSS_SIGNATURE_SIZE);
	for(i=0; i < MSS_SIGNATURE_SIZE; i++)
		printf("%02X", signature_serialization_buffer[i]);
	printf("\n*****************************************\n");
	//*/

	printf("Verifying signature...");

	if(mss_verify_core(authpath, node[0].value, message, strlen(message) + 1, &hash_mmo, &hash_dm, hash, node[0].index, ots, aux, &node[0], pkey))
		printf(" OK! - ");
	else
		printf(" Fail! - ");

	printf(" done!\n");
	printf("*****************************************\n");

	printf("*****************************************\n");
	printf("*                                       *\n");
	printf("*       MSS Integration Functions       *\n");
	printf("*                                       *\n");
	printf("*****************************************\n");

	unsigned char *keys_int, skey_int[MSS_SKEY_SIZE], pkey_int[MSS_PKEY_SIZE], *signature_int;

	printf("Generating key...");
	keys_int = mss_keygen(skey);
	printf(" done!\n");

	for(i = 0; i < MSS_SKEY_SIZE; i++)
		skey_int[i] = keys_int[i];
	for(i = 0; i < MSS_PKEY_SIZE; i++)
		pkey_int[i] = keys_int[MSS_SKEY_SIZE + i];

	sponge_state sponge;
	unsigned char digest[2 * MSS_SEC_LVL];

	sponge_hash(message, strlen(message), digest, 2 * MSS_SEC_LVL);
	printf("Signing message (obtaining %d OTS)...", EXAMPLE_Nth_SIGNATURE);
	for(i = 0; i < EXAMPLE_Nth_SIGNATURE; i++)
		signature_int = mss_sign(skey_int, digest);
	printf(" done!\n");

	base64encode(signature_int, MSS_SIGNATURE_SIZE, base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("Signature: %s\n", base64_buffer);

	printf("Verifying signature...");

	if(mss_verify(signature_int, pkey_int, digest))
		printf(" OK! - ");
	else
		printf(" Fail! - ");
	printf(" done!\n");

	return 0;
}

