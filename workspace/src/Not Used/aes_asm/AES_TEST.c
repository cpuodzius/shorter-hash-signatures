/*
 * AES_TEST.c
 *
 * Created: 29/05/2014 02:03:38
 *  Author: geovandro
 */ 

#include <avr/io.h>
#include <stdint.h>
#include "aes.h"

int main(void)
{
	/* a sample key, key must be located in RAM */
	uint8_t key[16]  = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
						0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	/* sample data, you can encrypt what you want but keep in mind that only 128 bits (not less not more) get encrypted*/
	uint8_t data[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
					  0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	aes128_ctx_t ctx; /* the context where the round keys are stored */
	aes128_init(key, &ctx); /* generating the round keys from the 128 bit key */
	aes128_enc(data, &ctx); /* encrypting the data block */
}