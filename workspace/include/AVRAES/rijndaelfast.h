#ifndef RIJNDAEL_FAST_H_
#define RIJNDAEL_FAST_H_

#include <stdint.h>

typedef struct{
	uint8_t ks[16];
} aes_roundkey_t;

typedef struct{
	aes_roundkey_t key[10+1];
} aes128_ctx_t;

void aes128_init(const void* key, aes128_ctx_t* aes128_ctx);
void aes128_enc(void* plaintext, aes128_ctx_t* aes128_ctx);

#endif
