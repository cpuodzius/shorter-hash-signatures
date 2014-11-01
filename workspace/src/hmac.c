#include <stdlib.h>
#include <string.h>

#include "hmac.h"

#include "aes_128.h"
#include "sponge.h"

void get_hmac(char *message, unsigned char key[AES_128_KEY_SIZE], unsigned char tag[HMAC_TAG_SIZE]) {
	sponge_state sponge;
	sponge_init(&sponge);
	sponge_absorb(&sponge, key, AES_128_KEY_SIZE);
	sponge_absorb(&sponge, (unsigned char *) message, strlen(message));
	sponge_squeeze(&sponge, tag, HMAC_TAG_SIZE);
}

unsigned char verify_hmac(unsigned char tag[HMAC_TAG_SIZE], char *message, unsigned char key[AES_128_KEY_SIZE]) {
	unsigned char tag_calc[HMAC_TAG_SIZE];
	get_hmac(message, key, tag_calc);
	return (memcmp(tag_calc, tag, HMAC_TAG_SIZE) == 0);
}

#ifdef HMAC_SELFTEST

#include <stdio.h>
#include "util.h"

int main() {
	char *message = "HMAC testing...";
	unsigned char key[AES_128_KEY_SIZE], tag[HMAC_TAG_SIZE];
	unsigned int i;

	printf("message:\n");
        printf("%s", message);
        printf("\n");

	printf("key:\n");
        for(i = 0; i < AES_128_KEY_SIZE; i++)
                printf("%02X ", key[i]);
        printf("\n");

	get_hmac(message, key, tag);

	printf("tag:\n");
        for(i = 0; i < HMAC_TAG_SIZE; i++)
                printf("%02X ", tag[i]);
        printf("\n");

	if(verify_hmac(tag, message, key))
		printf("HMAC OK!\n");
	else
		printf("HMAC FAIL!\n");

	return 0;
}

#endif // HMAC_SELFTEST
