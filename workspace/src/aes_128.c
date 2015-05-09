#include "aes_128.h"

#if !defined(AES_HW) && !defined(AES_ASM) 
	#ifdef AES_ENC_DEC
		#include "TI_aes_128.h"
	#else
		//#include "ti_aes.c"
	#endif
#endif //AES_SW

#include <string.h>

#ifdef DEBUG
	#include <assert.h>
#endif

//* Declaring this globally here is much more faster than inside a function for ATmega
unsigned char IV_MMO16[176] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                               0x62,0x63,0x63,0x63,0x62,0x63,0x63,0x63,0x62,0x63,0x63,0x63,0x62,0x63,0x63,0x63,
                               0x9B,0x98,0x98,0xC9,0xF9,0xFB,0xFB,0xAA,0x9B,0x98,0x98,0xC9,0xF9,0xFB,0xFB,0xAA,
                               0x90,0x97,0x34,0x50,0x69,0x6C,0xCF,0xFA,0xF2,0xF4,0x57,0x33,0x0B,0x0F,0xAC,0x99,
                               0xEE,0x06,0xDA,0x7B,0x87,0x6A,0x15,0x81,0x75,0x9E,0x42,0xB2,0x7E,0x91,0xEE,0x2B,
                               0x7F,0x2E,0x2B,0x88,0xF8,0x44,0x3E,0x09,0x8D,0xDA,0x7C,0xBB,0xF3,0x4B,0x92,0x90,
                               0xEC,0x61,0x4B,0x85,0x14,0x25,0x75,0x8C,0x99,0xFF,0x09,0x37,0x6A,0xB4,0x9B,0xA7,
                               0x21,0x75,0x17,0x87,0x35,0x50,0x62,0x0B,0xAC,0xAF,0x6B,0x3C,0xC6,0x1B,0xF0,0x9B,
                               0x0E,0xF9,0x03,0x33,0x3B,0xA9,0x61,0x38,0x97,0x06,0x0A,0x04,0x51,0x1D,0xFA,0x9F,
                               0xB1,0xD4,0xD8,0xE2,0x8A,0x7D,0xB9,0xDA,0x1D,0x7B,0xB3,0xDE,0x4C,0x66,0x49,0x41,
                               0xB4,0xEF,0x5B,0xCB,0x3E,0x92,0xE2,0x11,0x23,0xE9,0x51,0xCF,0x6F,0x8F,0x18,0x8E};
//*/

/*key is already expanded*/
void aes128_encrypt_keyexpanded(unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char plaintext[AES_128_BLOCK_SIZE]){//, const unsigned char expandedKey[11*AES_128_KEY_SIZE]) {

	memcpy(ciphertext,plaintext,AES_128_BLOCK_SIZE);
#ifdef PLATFORM_SENSOR
        aes128_enc(ciphertext,(aes128_ctx_t*)IV_MMO16);
#else
	aes_encr(ciphertext,IV_MMO16);
#endif
	
}

/**
 * Encrypt a single AES block under a 128-bit key.
 */
void aes_128_encrypt(unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char plaintext[AES_128_BLOCK_SIZE], const unsigned char key[AES_128_KEY_SIZE]) {
#if defined(PLATFORM_SENSOR) && defined(AES_HW) && defined(RADIO_CC2420)
	unsigned short i;
	cc2420_aes_set_key(key, 0);
	//printf("AES key:");
	//for (i = 0; i < AES_128_BLOCK_SIZE; i++) printf(" %02X", key[i]);
	//printf("AES plain:");
	//for (i = 0; i < AES_128_BLOCK_SIZE; i++) printf(" %02X", plaintext[i]);
	memcpy(ciphertext, plaintext, AES_128_BLOCK_SIZE); // ct saves the plaintext
	//for (i = 0; i < AES_128_BLOCK_SIZE; i++) {
	//      ciphertext[i] = plaintext[i];
	//}
	cc2420_aes_cipher(ciphertext, AES_128_BLOCK_SIZE, 0); // ct will be overwritten with the computed ciphertext
	//for (i = 0; i < AES_128_BLOCK_SIZE; i++) printf(" %02X", plaintext[i]);
	//printf("\n");

#elif defined(PLATFORM_SENSOR) && (defined(AES_ASM_2) || defined(AES_ASM_3)) && defined(PLATFORM_AVR)
	aes128_ctx_t aes_ctx; // the context where the round keys are stored
	aes128_init(key, &aes_ctx); // generating the round keys from the 128 bit key
	memcpy(ciphertext, plaintext, AES_128_BLOCK_SIZE);
	aes128_enc(ciphertext, &aes_ctx); // encrypting the data block
#else
	unsigned char local_key[AES_128_KEY_SIZE];
	memcpy(local_key,key,AES_128_KEY_SIZE);
	memcpy(ciphertext, plaintext, AES_128_BLOCK_SIZE); // c saves the plaintext
	#ifdef AES_ENC_DEC
		aes_enc_dec(ciphertext, local_key, 0); // TI_aes_128.c
	#else
		//aes_encrypt(/*c*/ciphertext, local_key); TI_aes_128_encr_only.c
		ti_aes_encrypt(ciphertext, local_key); // (ti_aes.c) ciphertext saves the plaintext
	#endif //AES_ENC_DEC
#endif
}

#ifdef AES_ENC_DEC
/**
 * Decrypt a single AES block under a 128-bit key.
 */
void aes_128_decrypt(unsigned char plaintext[AES_128_BLOCK_SIZE], const unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char key[AES_128_KEY_SIZE]) {
	unsigned char local_key[AES_128_KEY_SIZE];
	memcpy(local_key,key,AES_128_KEY_SIZE);
	memcpy(plaintext, ciphertext, AES_128_BLOCK_SIZE); // plaintext saves the ciphertext
	aes_enc_dec(plaintext, local_key, 1);
}

#ifdef AES_CBC_MODE

void padding_pkcs7(const char *plaintext, unsigned int plaintext_len, unsigned char *ciphertext, unsigned int *ciphertext_len) {
	unsigned int tail = plaintext_len % AES_128_BLOCK_SIZE;
	memcpy(ciphertext, plaintext, plaintext_len);
	memset(ciphertext + plaintext_len, AES_128_BLOCK_SIZE - tail, AES_128_BLOCK_SIZE - tail);
	*ciphertext_len = plaintext_len + (AES_128_BLOCK_SIZE - tail);
}

/**
 * aes_128_cbc_encrypt - AES-128 CBC encryption
 * @key: Encryption key
 * @iv: Encryption IV for CBC mode (AES_128_BLOCK_SIZE bytes)
 * @data: Data to encrypt in-place
 * @data_len: Length of data in bytes (must be divisible by AES_128_BLOCK_SIZE)
 */
void aes_128_cbc_encrypt(const unsigned char key[AES_128_KEY_SIZE], const unsigned char iv[AES_128_BLOCK_SIZE], const char *plaintext, unsigned char *ciphertext, unsigned int *ciphertext_len) {
	unsigned int i, j;

	unsigned char block[AES_128_BLOCK_SIZE];

	padding_pkcs7(plaintext, strlen(plaintext), ciphertext, ciphertext_len);

	for(i = 0; i < *ciphertext_len / AES_128_BLOCK_SIZE; i++) {
		if(i == 0) {
			for(j = 0; j < AES_128_BLOCK_SIZE; j++)
				block[j] = plaintext[j] ^ iv[j];
			aes_128_encrypt(block, block, key);
		}
		else {
			for(j = 0; j < AES_128_BLOCK_SIZE; j++)
				block[j] = plaintext[AES_128_BLOCK_SIZE * i + j] ^ block[j];
			aes_128_encrypt(block, block, key);
		}
		for(j = 0; j < AES_128_BLOCK_SIZE; j++)
			ciphertext[i * AES_128_BLOCK_SIZE + j] = block[j];
	}
}


/**
 * aes_128_cbc_decrypt - AES-128 CBC decryption
 * @key: Decryption key
 * @iv: Decryption IV for CBC mode (AES_128_BLOCK_SIZE bytes)
 * @data: Data to decrypt in-place
 * @data_len: Length of data in bytes (must be divisible by AES_128_BLOCK_SIZE)
 */
void aes_128_cbc_decrypt(const unsigned char key[AES_128_KEY_SIZE], const unsigned char iv[AES_128_BLOCK_SIZE], const unsigned char *ciphertext, unsigned int ciphertext_len, char *plaintext) {
	unsigned int i, j;

	unsigned char block[AES_128_BLOCK_SIZE];

	for(i = 0; i < ciphertext_len / AES_128_BLOCK_SIZE; i++) {
		aes_128_decrypt(block, ciphertext + i * AES_128_BLOCK_SIZE, key);
		for(j = 0; j < AES_128_BLOCK_SIZE; j++)
			if(i == 0)
				plaintext[j] = block[j] ^ iv[j];
			else
				plaintext[AES_128_BLOCK_SIZE * i + j] = block[j] ^ ciphertext[((i - 1) * AES_128_BLOCK_SIZE) + j];
	}

	plaintext[ciphertext_len - (plaintext[ciphertext_len - 1])] = '\0';
}

#endif //AES_CBC
#endif //AES_ENC_DEC

#include <stdio.h>
#include "util.h"

#if AES_SELFTEST

#define BUFFER_SIZE	300

int main() {
	unsigned int i;

	// AES 128
	unsigned char plaintext_block[AES_128_BLOCK_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	unsigned char ciphertext_block[AES_128_BLOCK_SIZE];
	unsigned char key[AES_128_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	aes_128_encrypt(ciphertext_block, plaintext_block, key);

	printf("ciphertext block:\n");
	for(i = 0; i < AES_128_BLOCK_SIZE; i++)
		printf("%02X ", ciphertext_block[i]);
	printf("\n");

	aes_128_decrypt(plaintext_block, ciphertext_block, key);

	printf("plaintext block:\n");
	for(i = 0; i < AES_128_BLOCK_SIZE; i++)
		printf("%02X ", plaintext_block[i]);
	printf("\n");

	// AES CBC
	char plaintext[BUFFER_SIZE] = "teste do AES-CBC: Cassius gosta de Dream Theater";
	unsigned char ciphertext[BUFFER_SIZE], buffer[BUFFER_SIZE];
	unsigned int size;
	unsigned char iv[AES_128_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	aes_128_cbc_encrypt(key, iv, plaintext, ciphertext, &size);

	printf("key:\n");
	for(i = 0; i < AES_128_KEY_SIZE; i++)
		printf("%02X ", key[i]);
	printf("\n");

	printf("plaintext:\n");
	printf("%s", plaintext);
	printf("\n");
	for(i = 0; i < strlen(plaintext); i++)
		printf("%02X ", plaintext[i]);
	printf("\n");

	printf("ciphertext:\n");
	for(i = 0; i < size; i++)
		printf("%02X ", ciphertext[i]);
	printf("\n");

	base64encode(key, AES_128_KEY_SIZE, buffer, BUFFER_SIZE);
	printf("key (base64): %s\n", buffer);
	base64encode(ciphertext, size, buffer, BUFFER_SIZE);
	printf("ciphertext (base64): %s\n", buffer);

	aes_128_cbc_decrypt(key, iv, ciphertext, size, plaintext);

	printf("plaintext:\n");
	for(i = 0; i < size; i++)
		printf("%02X ", plaintext[i]);
	printf("\n");
	printf("%s", plaintext);
	printf("\n");

	// PKCS#7 Padding
	char message[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	char message2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned int len = sizeof(message);
	unsigned int len2 = sizeof(message2);

	unsigned char padded[BUFFER_SIZE];
	unsigned int pad_len;

	padding_pkcs7(message, len, padded, &pad_len);

	printf("Padding 1:\n");
	for(i = 0; i < pad_len; i++)
		printf("%02X ", padded[i]);
	printf("\n");

	padding_pkcs7(message2, len2, padded, &pad_len);

	printf("Padding 2:\n");
	for(i = 0; i < pad_len; i++)
		printf("%02X ", padded[i]);
	printf("\n");

	return 0;
}

#undef BUFFER_SIZE
#endif
