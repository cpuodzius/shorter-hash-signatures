#include "mmo.h"
#include <string.h>

#ifdef DEBUG
	#include <assert.h>
#endif


/**
 * Encrypt a single AES block under a 128-bit key.
 */
/*
extern void AES_encrypt(unsigned char ct[16], const unsigned char pt[16], const unsigned char key[16]);
/*/
void AES_encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16], unsigned char key[16]) {

    #ifdef PLATFORM_TELOSB
/*
		unsigned short i;
		cc2420_aes_set_key(key, 0);
		//printf("AES key:");
		//for (i = 0; i < 16; i++) printf(" %02X", key[i]);
		//printf("AES plain:");
		//for (i = 0; i < 16; i++) printf(" %02X", plaintext[i]);
		memcpy(ciphertext, plaintext, 16); // ct saves the plaintext
		//for (i = 0; i < 16; i++) {
		//	ciphertext[i] = plaintext[i];
		//}
		cc2420_aes_cipher(ciphertext, 16, 0); // ct will be overwritten with the computed ciphertext
		//for (i = 0; i < 16; i++) printf(" %02X", plaintext[i]);
		//printf("\n");
/*/
		//cipherCryptB((u8*) key, (u8*) plaintext, ciphertext);
		memcpy(ciphertext, plaintext, 16); // ciphertext saves the plaintext
		aes_encrypt(ciphertext, key);

//*/
    #else
        //cipherCryptB((u8*) key, (u8*) plaintext, ciphertext);

		memcpy(ciphertext, plaintext, 16); // ciphertext saves the plaintext
		aes_encrypt(ciphertext, key);      // ciphertext is overwritten with its real value
    #endif // PLATFORM_SENSOR

}
//*/

void MMO_init(mmo_t *mmo) {
    mmo->t = 16; // one AES block
    mmo->n = 0;

    memset(mmo->H, 0, 16);
    memset(mmo->IV, 0, 16);
}

void MMO_update(mmo_t *mmo, const unsigned char *M, unsigned int m) {
    unsigned char *ZZ = &mmo->M[16 - mmo->t];
    mmo->n += m;
    for (;;) {
        switch ((m >= mmo->t) ? mmo->t : m) {
        case 16: ZZ[15] = M[15]; // FALLTHROUGH
        case 15: ZZ[14] = M[14]; // FALLTHROUGH
        case 14: ZZ[13] = M[13]; // FALLTHROUGH
        case 13: ZZ[12] = M[12]; // FALLTHROUGH
        case 12: ZZ[11] = M[11]; // FALLTHROUGH
        case 11: ZZ[10] = M[10]; // FALLTHROUGH
        case 10: ZZ[ 9] = M[ 9]; // FALLTHROUGH
        case  9: ZZ[ 8] = M[ 8]; // FALLTHROUGH
        case  8: ZZ[ 7] = M[ 7]; // FALLTHROUGH
        case  7: ZZ[ 6] = M[ 6]; // FALLTHROUGH
        case  6: ZZ[ 5] = M[ 5]; // FALLTHROUGH
        case  5: ZZ[ 4] = M[ 4]; // FALLTHROUGH
        case  4: ZZ[ 3] = M[ 3]; // FALLTHROUGH
        case  3: ZZ[ 2] = M[ 2]; // FALLTHROUGH
        case  2: ZZ[ 1] = M[ 1]; // FALLTHROUGH
        case  1: ZZ[ 0] = M[ 0]; // FALLTHROUGH
        case  0: break;
        }
        if (m < mmo->t) {
            break; // postpone incomplete message block
        }

        AES_encrypt(mmo->H, mmo->M, mmo->H);

        mmo->H[ 0] ^= mmo->M[ 0];
        mmo->H[ 1] ^= mmo->M[ 1];
        mmo->H[ 2] ^= mmo->M[ 2];
        mmo->H[ 3] ^= mmo->M[ 3];
        mmo->H[ 4] ^= mmo->M[ 4];
        mmo->H[ 5] ^= mmo->M[ 5];
        mmo->H[ 6] ^= mmo->M[ 6];
        mmo->H[ 7] ^= mmo->M[ 7];
        mmo->H[ 8] ^= mmo->M[ 8];
        mmo->H[ 9] ^= mmo->M[ 9];
        mmo->H[10] ^= mmo->M[10];
        mmo->H[11] ^= mmo->M[11];
        mmo->H[12] ^= mmo->M[12];
        mmo->H[13] ^= mmo->M[13];
        mmo->H[14] ^= mmo->M[14];
        mmo->H[15] ^= mmo->M[15];

        // proceed to the next block:
        m -= mmo->t;
        M += mmo->t;
        mmo->t = 16;
        ZZ = mmo->M;
#ifdef DEBUG
        assert(m > 0);
#endif
    }
    mmo->t -= m;
#ifdef DEBUG
    assert(mmo->t > 0);
#endif
    //assert(m == 0 || mmo->t < 16); // m == 0 here only occurs if m == 0 from the very beginning
}

void MMO_final(mmo_t *mmo, unsigned char tag[16]) {
    unsigned int i;
    unsigned char *ZZ = &mmo->M[16 - mmo->t];
#ifdef DEBUG
    assert(mmo->t > 0);
#endif
    // compute padding:
    *ZZ++ = 0x80; // padding toggle
    mmo->t--;

    if (mmo->t < 8) { // no space for 64-bit length field
        while (mmo->t > 0) {
            *ZZ++ = 0x00; // fill remainder of block with zero padding
            mmo->t--;
        }

        AES_encrypt(mmo->H, mmo->M, mmo->H);

        mmo->H[ 0] ^= mmo->M[ 0];
        mmo->H[ 1] ^= mmo->M[ 1];
        mmo->H[ 2] ^= mmo->M[ 2];
        mmo->H[ 3] ^= mmo->M[ 3];
        mmo->H[ 4] ^= mmo->M[ 4];
        mmo->H[ 5] ^= mmo->M[ 5];
        mmo->H[ 6] ^= mmo->M[ 6];
        mmo->H[ 7] ^= mmo->M[ 7];
        mmo->H[ 8] ^= mmo->M[ 8];
        mmo->H[ 9] ^= mmo->M[ 9];
        mmo->H[10] ^= mmo->M[10];
        mmo->H[11] ^= mmo->M[11];
        mmo->H[12] ^= mmo->M[12];
        mmo->H[13] ^= mmo->M[13];
        mmo->H[14] ^= mmo->M[14];
        mmo->H[15] ^= mmo->M[15];

        mmo->t = 16; // start new block
        ZZ = mmo->M;
    }
#ifdef DEBUG
    assert(mmo->t >= 8);
#endif
    while (mmo->t > 8) {
        *ZZ++ = 0x00; // fill low half of block with zero padding
        mmo->t--;
    }
#ifdef DEBUG
    assert(mmo->t == 8);
#endif
    mmo->n <<= 3; // convert unsigned char length to bit length
    ZZ += 8;
    for (i = 0; i < 8; i++) {
        *--ZZ = mmo->n & 0xff;
        mmo->n >>= 8; // this is overkill if mmo->n is too short, but it is correct and general
    }

	AES_encrypt(mmo->H, mmo->M, mmo->H);

    mmo->H[ 0] ^= mmo->M[ 0];
    mmo->H[ 1] ^= mmo->M[ 1];
    mmo->H[ 2] ^= mmo->M[ 2];
    mmo->H[ 3] ^= mmo->M[ 3];
    mmo->H[ 4] ^= mmo->M[ 4];
    mmo->H[ 5] ^= mmo->M[ 5];
    mmo->H[ 6] ^= mmo->M[ 6];
    mmo->H[ 7] ^= mmo->M[ 7];
    mmo->H[ 8] ^= mmo->M[ 8];
    mmo->H[ 9] ^= mmo->M[ 9];
    mmo->H[10] ^= mmo->M[10];
    mmo->H[11] ^= mmo->M[11];
    mmo->H[12] ^= mmo->M[12];
    mmo->H[13] ^= mmo->M[13];
    mmo->H[14] ^= mmo->M[14];
    mmo->H[15] ^= mmo->M[15];

    memcpy(tag, mmo->H, 16);

    mmo->t = 16; // reset
    mmo->n = 0;
}

void MMO_hash16(mmo_t *mmo, const unsigned char M[16], unsigned char tag[16]) {
    unsigned char *H = mmo->H;
    //unsigned char *ZZ = mmo->M;

    memset(H, 0, 16);
    memset(&H[0], 1, 1);

    AES_encrypt(H, M, H);

    H[ 0] ^= M[ 0];
    H[ 1] ^= M[ 1];
    H[ 2] ^= M[ 2];
    H[ 3] ^= M[ 3];
    H[ 4] ^= M[ 4];
    H[ 5] ^= M[ 5];
    H[ 6] ^= M[ 6];
    H[ 7] ^= M[ 7];
    H[ 8] ^= M[ 8];
    H[ 9] ^= M[ 9];
    H[10] ^= M[10];
    H[11] ^= M[11];
    H[12] ^= M[12];
    H[13] ^= M[13];
    H[14] ^= M[14];
    H[15] ^= M[15];

/*
    // compute padding:
    memset(ZZ, 0, 16);
    ZZ[ 0] = 0x80; // padding toggle
    ZZ[15] = 0x80; // 128-bit length

    AES_encrypt(H, ZZ, H);

    //
    H[ 0] ^= ZZ[ 0];
    H[ 1] ^= ZZ[ 1];
    H[ 2] ^= ZZ[ 2];
    H[ 3] ^= ZZ[ 3];
    H[ 4] ^= ZZ[ 4];
    H[ 5] ^= ZZ[ 5];
    H[ 6] ^= ZZ[ 6];
    H[ 7] ^= ZZ[ 7];
    H[ 8] ^= ZZ[ 8];
    H[ 9] ^= ZZ[ 9];
    H[10] ^= ZZ[10];
    H[11] ^= ZZ[11];
    H[12] ^= ZZ[12];
    H[13] ^= ZZ[13];
    H[14] ^= ZZ[14];
    H[15] ^= ZZ[15];
    //*/

    memcpy(tag, H, 16);
}

void MMO_hash32(mmo_t *mmo, const unsigned char M[32], unsigned char tag[16]) {
    unsigned char *H = mmo->H;
    //unsigned char *ZZ = mmo->M;

    memset(H, 0, 16);
    memset(&H[0], 2, 1);

    AES_encrypt(H, M, H);

    H[ 0] ^= M[ 0];
    H[ 1] ^= M[ 1];
    H[ 2] ^= M[ 2];
    H[ 3] ^= M[ 3];
    H[ 4] ^= M[ 4];
    H[ 5] ^= M[ 5];
    H[ 6] ^= M[ 6];
    H[ 7] ^= M[ 7];
    H[ 8] ^= M[ 8];
    H[ 9] ^= M[ 9];
    H[10] ^= M[10];
    H[11] ^= M[11];
    H[12] ^= M[12];
    H[13] ^= M[13];
    H[14] ^= M[14];
    H[15] ^= M[15];

    M += 16;

    AES_encrypt(H, M, H);

    H[ 0] ^= M[ 0];
    H[ 1] ^= M[ 1];
    H[ 2] ^= M[ 2];
    H[ 3] ^= M[ 3];
    H[ 4] ^= M[ 4];
    H[ 5] ^= M[ 5];
    H[ 6] ^= M[ 6];
    H[ 7] ^= M[ 7];
    H[ 8] ^= M[ 8];
    H[ 9] ^= M[ 9];
    H[10] ^= M[10];
    H[11] ^= M[11];
    H[12] ^= M[12];
    H[13] ^= M[13];
    H[14] ^= M[14];
    H[15] ^= M[15];

/*
    // compute padding:
    memset(ZZ, 0, 16);
    ZZ[ 0] = 0x80; // padding toggle
    ZZ[14] = 0x01; // 256-bit length

    //AES_encrypt(H, ZZ, H);
	cc2420_aes_set_key(H, 0);
	memcpy(H, ZZ, 16); // H saves the plaintext which will be overwritten in aes_cipher
	cc2420_aes_cipher(H, 16, 0); // H will be overwritten with the ciphertext

    //
    H[ 0] ^= ZZ[ 0];
    H[ 1] ^= ZZ[ 1];
    H[ 2] ^= ZZ[ 2];
    H[ 3] ^= ZZ[ 3];
    H[ 4] ^= ZZ[ 4];
    H[ 5] ^= ZZ[ 5];
    H[ 6] ^= ZZ[ 6];
    H[ 7] ^= ZZ[ 7];
    H[ 8] ^= ZZ[ 8];
    H[ 9] ^= ZZ[ 9];
    H[10] ^= ZZ[10];
    H[11] ^= ZZ[11];
    H[12] ^= ZZ[12];
    H[13] ^= ZZ[13];
    H[14] ^= ZZ[14];
    H[15] ^= ZZ[15];
    //*/

    memcpy(tag, H, 16);
}

void davies_meyer_hash16(unsigned char IV[16], const unsigned char M[16], unsigned char tag[16]) {
    AES_encrypt(tag, M, IV);
}

void davies_meyer_hash32(unsigned char IV[16], const unsigned char M0[16], const unsigned char M1[16], unsigned char tag[16]) {

    unsigned char tmp[16];

    memcpy(tmp, M1, 16); // this was need because M1 and tag are the same memory address from merkle's algorithm

    IV[0] = 1;
    AES_encrypt(tag, M0, IV);
    tag[0] ^= 0x01;
    IV[0] = 0;

    AES_encrypt(tmp, tmp, tag);

    tag[ 0] ^= tmp[ 0];
    tag[ 1] ^= tmp[ 1];
    tag[ 2] ^= tmp[ 2];
    tag[ 3] ^= tmp[ 3];
    tag[ 4] ^= tmp[ 4];
    tag[ 5] ^= tmp[ 5];
    tag[ 6] ^= tmp[ 6];
    tag[ 7] ^= tmp[ 7];
    tag[ 8] ^= tmp[ 8];
    tag[ 9] ^= tmp[ 9];
    tag[10] ^= tmp[10];
    tag[11] ^= tmp[11];
    tag[12] ^= tmp[12];
    tag[13] ^= tmp[13];
    tag[14] ^= tmp[14];
    tag[15] ^= tmp[15];
}


#ifdef MMO_SELFTEST
int main(int argc, char *argv[]) {
    unsigned int i;
    mmo_t mmo;
    char *msg16 = "0123456789ABCDEF";
    char *msg32 = "0123456789ABCDEF0123456789ABCDEF";
    unsigned char tag[16];

    MMO_init(&mmo);
    MMO_update(&mmo, (unsigned char *)msg, 16);
    MMO_final(&mmo, tag);
    for (i = 0; i < 16; i++) {
        printf("%02X", tag[i]);
    }
    printf("\n");
    return 0;
}
#endif
