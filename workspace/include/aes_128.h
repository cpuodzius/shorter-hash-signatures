#ifndef __AES_128_H_
#define __AES_128_H_

#define AES_128_BLOCK_SIZE	16
#define AES_128_KEY_SIZE	16

void aes_128_encrypt(unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char plaintext[AES_128_BLOCK_SIZE], unsigned char key[AES_128_KEY_SIZE]);

#ifdef AES_ENC_DEC
#ifdef AES_CBC_MODE

void aes_128_decrypt(unsigned char plaintext[AES_128_BLOCK_SIZE], const unsigned char ciphertext[AES_128_BLOCK_SIZE], unsigned char key[AES_128_KEY_SIZE]);

void aes_128_cbc_encrypt(const unsigned char key[AES_128_KEY_SIZE], const unsigned char iv[AES_128_BLOCK_SIZE], unsigned char *data, unsigned int data_len);
void aes_128_cbc_decrypt(const unsigned char key[AES_128_KEY_SIZE], const unsigned char iv[AES_128_BLOCK_SIZE], unsigned char *data, unsigned int data_len);

#endif	//AES_CBC
#endif	//AES_DECRYPT

#endif /* __AES_128_H_ */
