#include "aes_128.h"
#include <string.h>

#if !defined(AES_HW) && !defined(AES_ASM) 
#ifdef AES_ENC_DEC
#include "TI_aes_128.h"
#else
#include "TI_aes_128_encr_only.h"
#endif
#endif //AES_SW

#ifdef DEBUG
	#include <assert.h>
#endif

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

#elif defined(PLATFORM_SENSOR) && defined(AES_ASM) && defined(PLATFORM_ATMEL)
	aes128_ctx_t ctx_mmo; // the context where the round keys are stored
	aes128_init(key, &ctx_mmo); // generating the round keys from the 128 bit key
	memcpy(ciphertext, plaintext, AES_128_BLOCK_SIZE);
	aes128_enc(ciphertext, &ctx_mmo); // encrypting the data block
#else
	unsigned char local_key[AES_128_KEY_SIZE];
	memcpy(local_key,key,AES_128_KEY_SIZE);
	memcpy(ciphertext, plaintext, AES_128_BLOCK_SIZE); // ciphertext saves the plaintext
#ifdef AES_ENC_DEC
	aes_enc_dec(ciphertext, local_key, 0);
#else
	aes_encrypt(ciphertext, local_key); // ciphertext is overwritten with its final value
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
