#include "hash.h"
#include "aes_128.h"
#include <string.h>

#ifdef DEBUG
	#include <assert.h>
#endif

unsigned char IV_MMO[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

void MMO_init(mmo_t *mmo) {
    mmo->t = 16; // one AES block
    mmo->n = 0;

    memset(mmo->H, 0, 16);
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
	//memcpy(local_key,mmo->H,16);
        aes_128_encrypt(mmo->H, mmo->M, mmo->H);

#ifdef PLATFORM_SENSOR
        // This is faster than XORing each byte at a time
        ((int32_t *)mmo->H)[0] ^= ((int32_t *)mmo->M)[0];
        ((int32_t *)mmo->H)[1] ^= ((int32_t *)mmo->M)[1];
        ((int32_t *)mmo->H)[2] ^= ((int32_t *)mmo->M)[2];
        ((int32_t *)mmo->H)[3] ^= ((int32_t *)mmo->M)[3];    
#else    
        unsigned char i;
        for(i=0; i < (16 / sizeof(int));i++) { 
            ((int*)mmo->H)[i] ^= ((int*)mmo->M)[i];
        }
#endif   

        // proceed to the next block:
        m -= mmo->t;
        M += mmo->t;
        mmo->t = 16;
        ZZ = mmo->M;
#ifdef DEBUG
        //assert(m > 0);
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
        aes_128_encrypt(mmo->H, mmo->M, mmo->H);

#ifdef PLATFORM_SENSOR
        // This is faster than XORing each byte at a time
        ((int32_t *)mmo->H)[0] ^= ((int32_t *)mmo->M)[0];
        ((int32_t *)mmo->H)[1] ^= ((int32_t *)mmo->M)[1];
        ((int32_t *)mmo->H)[2] ^= ((int32_t *)mmo->M)[2];
        ((int32_t *)mmo->H)[3] ^= ((int32_t *)mmo->M)[3];    
#else   
        for(i=0; i < (16 / sizeof(int));i++) { 
            ((int*)mmo->H)[i] ^= ((int*)mmo->M)[i];
        }
#endif   

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
	//memcpy(local_key,mmo->H,16);
	aes_128_encrypt(mmo->H, mmo->M, mmo->H);

#ifdef PLATFORM_SENSOR
    // This is faster than XORing each byte at a time
    ((int32_t *)mmo->H)[0] ^= ((int32_t *)mmo->M)[0];
    ((int32_t *)mmo->H)[1] ^= ((int32_t *)mmo->M)[1];
    ((int32_t *)mmo->H)[2] ^= ((int32_t *)mmo->M)[2];
    ((int32_t *)mmo->H)[3] ^= ((int32_t *)mmo->M)[3];    
#else    
    for(i=0; i < (16 / sizeof(int));i++) { 
        ((int*)mmo->H)[i] ^= ((int*)mmo->M)[i];
    }
#endif   

    memcpy(tag, mmo->H, 16);

    mmo->t = 16; // reset
    mmo->n = 0;
}

void MMO_hash16(mmo_t *mmo, const unsigned char M[16], unsigned char tag[16]) {
    unsigned char i;
  
    //IV=0 already initialized as suggested in "Hash-based Signatures on Smart Cards", Busold 2012    
    aes_128_encrypt(mmo->H, M, IV_MMO);

#ifdef PLATFORM_SENSOR
    // This is faster than XORing each byte at a time
    ((int32_t *)mmo->H)[0] ^= ((int32_t *)M)[0];
    ((int32_t *)mmo->H)[1] ^= ((int32_t *)M)[1];
    ((int32_t *)mmo->H)[2] ^= ((int32_t *)M)[2];
    ((int32_t *)mmo->H)[3] ^= ((int32_t *)M)[3];    
#else    
    for(i=0; i < (16 / sizeof(int));i++) { 
        ((int*)mmo->H)[i] ^= ((int*)M)[i];
    }
#endif    

    memcpy(tag, mmo->H, 16);
}

void MMO_hash32(mmo_t *mmo, const unsigned char M1[16], const unsigned char M2[16], unsigned char tag[16]) {
        
    memset(mmo->H, 0, 16);
    memset(&mmo->H[0], 1, 1); // A fixed and different IV from MMO_hash16
 
    aes_128_encrypt(mmo->H, M1, mmo->H);

#ifdef PLATFORM_SENSOR    
    ((int32_t *)mmo->H)[0] ^= ((int32_t *)M1)[0];
    ((int32_t *)mmo->H)[1] ^= ((int32_t *)M1)[1];
    ((int32_t *)mmo->H)[2] ^= ((int32_t *)M1)[2];
    ((int32_t *)mmo->H)[3] ^= ((int32_t *)M1)[3];
#else
    unsigned char i;
    for(i=0; i < (16 / sizeof(int));i++) { 
        ((int*)mmo->H)[i] ^= ((int*)M1)[i];
    }
#endif

    aes_128_encrypt(mmo->H, M2, mmo->H);

#ifdef PLATFORM_SENSOR
    // This is faster than XORing each byte at a time
    ((int32_t *)mmo->H)[0] ^= ((int32_t *)M2)[0];
    ((int32_t *)mmo->H)[1] ^= ((int32_t *)M2)[1];
    ((int32_t *)mmo->H)[2] ^= ((int32_t *)M2)[2];
    ((int32_t *)mmo->H)[3] ^= ((int32_t *)M2)[3];
#else
    for(i=0; i < (16 / sizeof(int));i++) { 
        ((int*)mmo->H)[i] ^= ((int*)M2)[i];
    }
#endif

    memcpy(tag, mmo->H, 16);
}

/*
//Forward secure pseudo-random generator proposed in Christoph Busold's thesis
// (out1,out2) = (AES_{seed}(counter), AES_{seed}(counter+1))
void fsprg(unsigned char seed[16], unsigned char out1[16], unsigned char out2[16]) {
    memset(out2, 0, 16); // out2 is used as a 16-byte vector input of AES-encrypt holding the value of counter
    memcpy(out2, &fsprg_counter, sizeof(short));
    aes_128_encrypt(out1, out2, seed);
    fsprg_counter++;
    memcpy(out2, &fsprg_counter, sizeof(short));
    aes_128_encrypt(out2, out2, seed);
    fsprg_counter++;
}

void fsprg_restart() {
    fsprg_counter = 0;
}
//*/

void prg16(short input, const unsigned char seed[16], unsigned char output[16]) {
        memset(output, 0, 16);
        memcpy(output, &input, sizeof(short));
        aes_128_encrypt(output, output, seed);
}


#ifdef MMO_SELFTEST

#include <stdio.h>

int main(int argc, char *argv[]) {
    unsigned int i;
    mmo_t mmo;
    char *msg16 = "0123456789ABCDEF";
    unsigned char tag[16];

    MMO_init(&mmo);
    MMO_update(&mmo, (unsigned char *)msg16, 16);
    MMO_final(&mmo, tag);
    for (i = 0; i < 16; i++) {
        printf("%02X", tag[i]);
    }
    printf("\n");
    return 0;
}
#endif
