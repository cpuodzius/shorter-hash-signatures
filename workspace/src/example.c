/*
 * This function provides usage examples of the library
 */

#include <stdio.h>
#include <string.h>
#include "mss.h"

#define EXAMPLE_Nth_SIGNATURE	13
#define EXAMPLE_BASE64_BUFFER_SIZE	3000

#define SERIALIZATION_MSS_NODE_SIZE	(3 + LEN_BYTES(MSS_SEC_LVL))
#define SERIALIZATION_SIGNATURE_SIZE	(2 + MSS_HEIGHT * SERIALIZATION_MSS_NODE_SIZE + SERIALIZATION_MSS_NODE_SIZE + WINTERNITZ_L * LEN_BYTES(WINTERNITZ_SEC_LVL))

int base64encode(const void* data_buf, int data_size, char* result, int result_size);
void serialize(const unsigned char *ots, unsigned short index, const struct mss_node *v, const const struct mss_node authpath[MSS_HEIGHT], char *buffer, int buffer_size);

int main() {
	printf("MSS library utilization example...\n");

	int i;
	char base64_buffer[EXAMPLE_BASE64_BUFFER_SIZE];
	char signature_serialization_buffer[EXAMPLE_BASE64_BUFFER_SIZE];


	/* Auxiliary varibles */
	struct mss_node node[3];
	unsigned char hash[LEN_BYTES(WINTERNITZ_N)];
	unsigned char ots[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
	unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];

	mmo_t hash_mmo;
	dm_t hash_dm;

	/* Merkle-tree variables */
	struct state_mt state;
	struct mss_node authpath[MSS_HEIGHT];

	unsigned char pkey[NODE_VALUE_SIZE];
	unsigned char skey[LEN_BYTES(MSS_SEC_LVL)] = {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F};

	printf("...variables declared\nInitializing hashes and merkle tree state...");

	/* Initialization of Merkle–Damgård hash */
	DM_init(&hash_dm);
	
	/* Initialization of Winternitz-MMO OTS */
	sinit(&hash_mmo, MSS_SEC_LVL);

	printf(" done!\nGenerating key...");

	mss_keygen(&hash_dm, &hash_mmo, skey, &node[0], &node[1], &state, pkey);

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
		mss_sign(&state, skey, &node[0], M, strlen(M) + 1, &hash_mmo, &hash_dm, hash, i, &node[1], &node[2], ots, authpath);
	i--;

	printf(" done!\n");

	serialize(ots, i, &node[0], authpath, signature_serialization_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	base64encode(signature_serialization_buffer, SERIALIZATION_SIGNATURE_SIZE, base64_buffer, EXAMPLE_BASE64_BUFFER_SIZE);
	printf("sig: %s\n", base64_buffer);

	printf("Verifying signature...");

	mss_verify(authpath, node[0].value, M, strlen(M) + 1, &hash_mmo, &hash_dm, hash, i, ots, aux, &node[0], pkey);

	printf(" done!\n");

	return 0;
}

int base64encode(const void* data_buf, int data_size, char* result, int result_size)
{
   const char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   const unsigned char *data = (const char *)data_buf;
   int result_index = 0;
   int x;
   unsigned int n = 0;
   int pad_count = data_size % 3;
   unsigned char n0, n1, n2, n3;
 
   /* increment over the length of the string, three characters at a time */
   for (x = 0; x < data_size; x += 3) 
   {
      /* these three 8-bit (ASCII) characters become one 24-bit number */
      n = data[x] << 16;
 
      if((x+1) < data_size)
         n += data[x+1] << 8;
 
      if((x+2) < data_size)
         n += data[x+2];
 
      /* this 24-bit number gets separated into four 6-bit numbers */
      n0 = (unsigned char)(n >> 18) & 63;
      n1 = (unsigned char)(n >> 12) & 63;
      n2 = (unsigned char)(n >> 6) & 63;
      n3 = (unsigned char)n & 63;
 
      /*
       * if we have one byte available, then its encoding is spread
       * out over two characters
       */
      if(result_index >= result_size) return 1;   /* indicate failure: buffer too small */
      result[result_index++] = base64chars[n0];
      if(result_index >= result_size) return 1;   /* indicate failure: buffer too small */
      result[result_index++] = base64chars[n1];
 
      /*
       * if we have only two bytes available, then their encoding is
       * spread out over three chars
       */
      if((x+1) < data_size)
      {
         if(result_index >= result_size) return 1;   /* indicate failure: buffer too small */
         result[result_index++] = base64chars[n2];
      }
 
      /*
       * if we have all three bytes available, then their encoding is spread
       * out over four characters
       */
      if((x+2) < data_size)
      {
         if(result_index >= result_size) return 1;   /* indicate failure: buffer too small */
         result[result_index++] = base64chars[n3];
      }
   }  
 
   /*
    * create and add padding that is required if we did not have a multiple of 3
    * number of characters available
    */
   if (pad_count > 0) 
   { 
      for (; pad_count < 3; pad_count++) 
      { 
         if(result_index >= result_size) return 1;   /* indicate failure: buffer too small */
         result[result_index++] = '=';
      } 
   }
   if(result_index >= result_size) return 1;   /* indicate failure: buffer too small */
   result[result_index] = 0;
   return 0;   /* indicate success */
}

void serialize_mss_node(const struct mss_node node, char buffer[SERIALIZATION_MSS_NODE_SIZE]) {
	buffer[0] = node.height;
	buffer[1] = node.index & 0xFF;
	buffer[2] = (node.index >> 8) & 0xFF;

	int i;
	for (i = 0; i < LEN_BYTES(MSS_SEC_LVL); i++)
		buffer[3 + i] = node.value[i];
}

void serialize(const unsigned char *ots, unsigned short index, const struct mss_node *v, const const struct mss_node authpath[MSS_HEIGHT], char *buffer, int buffer_size) {
	/*
	 * Serialization: index || v || authpath || ots
	 *
	*/
	char buffer_mss_node[SERIALIZATION_MSS_NODE_SIZE];
	int i, j, k = 0;

	buffer[k++] = (index & 0xFF);
	buffer[k++] = ((index >> 8) & 0xFF);

	serialize_mss_node(*v, buffer_mss_node);
	for(i = 0; i < SERIALIZATION_MSS_NODE_SIZE; i++)
		buffer[k++] = buffer_mss_node[i];

	for(i = 0; i < MSS_HEIGHT; i++) {
		serialize_mss_node(authpath[i], buffer_mss_node);
		for(j = 0; j < SERIALIZATION_MSS_NODE_SIZE; j++)
			buffer[k++] = buffer_mss_node[j];
	}

	for(i = 0; i < SERIALIZATION_SIGNATURE_SIZE; i++)
		buffer[k++] = ots[i];
}

