#ifndef TI_AES
#define TI_AES

/*
#ifdef PLATFORM_TELOSB
	#include <avr/eeprom.h>
	#define rb(value) eeprom_read_byte((unsigned char*)value)
	#define sbox(value) (rb(sBox+(value)))
#endif//*/

void ti_aes_encrypt(unsigned char *state, unsigned char *key);

#endif
