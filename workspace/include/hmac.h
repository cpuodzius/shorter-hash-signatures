#ifndef __HMAC_H
#define __HMAC_H

#define HMAC_TAG_SIZE	16

void get_hmac(char *message, unsigned char key[], unsigned char tag[HMAC_TAG_SIZE]);
unsigned char verify_hmac(unsigned char tag[HMAC_TAG_SIZE], char *message, unsigned char key[]);

#endif /* __HMAC_H */
