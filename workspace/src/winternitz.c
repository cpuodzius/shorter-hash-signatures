#ifndef PLATFORM_TELOSB
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#endif

#include <string.h>

#include "winternitz.h"

/**
 * Compute a Winternitz public key v = H_m(x_{0}^{2^w-1}, x_{1}^{2^w-1}, ..., x_{L-1}^{2^w-1}), with L = (8/w)*m + ceil(lg((2^w-1)*m)/w), m = seclevel/8.
 *
 * @param s         the m-unsigned char private signing key.
 * @param m         hash length (sec level is 8*m).
 * @param v         the corresponding m-unsigned char verification key.
 * @param priv
 * @param hash
 * @param pubk
 * @param v
 */
void winternitz_keygen(const unsigned char s[/*m*/], const unsigned short m, mmo_t *pubk, dm_t *f, unsigned char v[/*m*/]) {
    //int sq = 0;
    unsigned char i, j;

#ifdef DEBUG
	#if WINTERNITZ_W == 2
		assert(10 <= m && m <= 21); // lower bound: min sec level (80 bits), upper bound: max checksum count must fit one byte
	#elif WINTERNITZ_W == 4
	    // NB: for 9 <= m <= 136, the value of ceil(lg(15*2*m)/8) is simply 3 nybbles.
	    assert(10 <= m && m <= 127); // lower bound: min sec level (80 bits), upper bound: max nybble count 2*(m-1)+3 must fit one unsigned char
	#elif WINTERNITZ_W == 8
	    // NB: for 2 <= m <= 257, the value of ceil(lg(255*m)/8) is simply 2 unsigned chars.
	    //TODO: do the assert
	#endif
	    assert((8 / WINTERNITZ_W)*(unsigned char)m + WINTERNITZ_CHECKSUM_SIZE == WINTERNITZ_L); // chunk count, including checksum
#endif

    sinit(pubk, WINTERNITZ_SEC_LVL);

    for (i = 0; i < WINTERNITZ_L; i++) { // chunk count, including checksum
        memset(v, 0, 16); v[0] = i; // H(s, i) // i = byte tag
        AES_encrypt(v, v, (unsigned char*)s); // v = s_i = private block for i-th byte
        //sq++;
        for (j = 0; j < (1 << WINTERNITZ_W) - 1; j++) {
            hash16(f, v, v); // v is the hash of its previous value = y_i = H^{2^w-1}(s_i)
            //sq++;
        }
        //absorb(pubk, v, m);  // y_0 || ... || y_i ...
	//memcpy(local_key,pubk->H,16);
        AES_encrypt(pubk->H, v, pubk->H);
        pubk->H[ 0] ^= v[ 0];
        pubk->H[ 1] ^= v[ 1];
        pubk->H[ 2] ^= v[ 2];
        pubk->H[ 3] ^= v[ 3];
        pubk->H[ 4] ^= v[ 4];
        pubk->H[ 5] ^= v[ 5];
        pubk->H[ 6] ^= v[ 6];
        pubk->H[ 7] ^= v[ 7];
        pubk->H[ 8] ^= v[ 8];
        pubk->H[ 9] ^= v[ 9];
        pubk->H[10] ^= v[10];
        pubk->H[11] ^= v[11];
        pubk->H[12] ^= v[12];
        pubk->H[13] ^= v[13];
        pubk->H[14] ^= v[14];
        pubk->H[15] ^= v[15];

    }
    //squeeze(pubk, v, m); // v is finally the public key, v = H(y_0 || y_1 || ... || y_{L-1})
    memcpy(v, pubk->H,16);
    //sq++;
    //printf("gen squeeze count: %d\n", sq);
    cleanup(pubk);
}

#if WINTERNITZ_W == 2

/**
 * Sign H(v, M) under private key s, yielding (x_{0:0}, x_{0:1}, x_{0:2}, x_{0:3}, ..., x_{(m-1):0}, x_{(m-1):1}, x_{(m-1):2}, x_{(m-1):3})
 *
 * @param s         the m-byte private signing key.
 * @param v         the corresponding m-byte verification key, used here as the random nonce.
 * @param m         hash length in bytes (sec level is 8*m).
 * @param M
 * @param len
 * @param priv
 * @param hash
 * @param h         buffer for message hash
 * @param sig
 */
void winternitz_2_sign(const unsigned char s[/*m*/], const unsigned char v[/*m*/], const unsigned short m, const char *M, unsigned short len,
                       mmo_t *hash, dm_t *f, unsigned char h[/*m*/], unsigned char sig[/*4*(m+1)*m*/] /* 4*(m+1) m-byte blocks */) {
    //int sq = 0;
    unsigned char i;
    unsigned short checksum = 0;

    //*
    memset(h,2,m); //TODO: change this to a true hash
	/*/
    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // public key used as random nonce!!!
    absorb(hash, M, len); // followed by the message in this implementation (actually followed by the treetop key, and then by the message, in the full scheme)
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //*/
    //sq++;


#ifdef DEBUG
    assert(10 <= m && m <= 21); // lower bound: min sec level (80 bits), upper bound: max checksum count must fit one byte
#endif

    // data part:
    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // 0 part:
        memset(sig, 0, 16); sig[0] = (i << 2) + 0; // H(s, 4i + 0) // 0 chunk index
        AES_encrypt(sig, sig, (unsigned char *)s); //sig = s_i = AES_s(i) // sig holds the private block for i-th "0" chunk
        //sq++;
        checksum += 3;
        switch ((h[i]     ) & 3) { // 0 chunk
        case 3:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 2:
              hash16(f,sig,sig); // sig holds the hash of its previous value
              //sq++;
            checksum--; // FALLTHROUGH
        case 1:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        sig += 16; // signature block for next chunk

        // 1 part:
        memset(sig, 0, 16); sig[0] = (i << 2) + 1; // H(s, 4i + 1) // 1 chunk index
        AES_encrypt(sig, sig, (unsigned char *)s); //sig = s_i = AES_s(i) // sig holds the private block for i-th "1" chunk
        //sq++;
        checksum += 3;
        switch ((h[i] >> 2) & 3) { // 1 chunk
        case 3:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 2:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 1:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        sig += 16; // signature block for next chunk

        // 2 part:
        memset(sig, 0, 16); sig[0] = (i << 2) + 2; // H(s, 4i + 2) // 2 chunk index
        AES_encrypt(sig, sig, (unsigned char *)s); //sig = s_i = AES_s(i) // sig holds the private block for i-th "2" chunk
        //sq++;
        checksum += 3;
        switch ((h[i] >> 4) & 3) { // 2 chunk
        case 3:
            //sq++;
            checksum--; // FALLTHROUGH
        case 2:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 1:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        sig += 16; // signature block for next chunk

        // 3 part:
        memset(sig, 0, 16); sig[0] = (i << 2) + 3; // H(s, 4i + 3) // 3 chunk index
        AES_encrypt(sig, sig, (unsigned char *)s); //sig = s_i = AES_s(i) // sig holds the private block for i-th "3" chunk
        //sq++;
        checksum += 3;
        switch ((h[i] >> 6) & 3) { // 3 chunk
        case 3:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 2:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 1:
              hash16(f,sig,sig);  // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        sig += 16; // signature block for next chunk
    }

    // checksum part:
    for (i = 0; i < WINTERNITZ_l2; i++) { // checksum
        memset(sig, 0, 16); sig[0] = (m << 2) + i; // H(s, 4m + i) // i-th chunk index
        AES_encrypt(sig, sig, (unsigned char *)s);  //sig = s_i = AES_s(i) // sig holds the private block for i-th checksum chunk
        //sq++;
        switch (checksum & 3) { // 3 chunk
        case 3:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            // FALLTHROUGH
        case 2:
              hash16(f,sig,sig); // sig holds the hash of its previous value
            //sq++;
            // FALLTHROUGH
        case 1:
              hash16(f,sig,sig);  // sig holds the hash of its previous value
            //sq++;
            // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        checksum >>= 2;
        sig += 16; // signature block for next nybble
    }
    //printf("sig squeeze count: %d\n", sq);
    cleanup(hash);
}
#endif // WINTERNITZ_W == 2


#if WINTERNITZ_W == 4

/**
 * Sign H(v, M) under private key s, yielding (x_{0:lo}, x_{0:hi}, ..., x_{(m-1):lo}, x_{(m-1):hi})
 *
 * @param s the m-unsigned char private signing key.
 * @param v the corresponding m-unsigned char verification key, used here as the random nonce.
 * @param m hash length (sec level is 8*m).
 * @param M
 * @param len
 * @param priv
 * @param hash
 * @param h buffer for message hash
 * @param sig
 */
void winternitz_4_sign(const unsigned char s[/*m*/], const unsigned char v[/*m*/], const unsigned short m, const char *M, unsigned short len,
                       mmo_t *hash, dm_t *f, unsigned char h[/*m*/], unsigned char sig[/*(2*m+3)*m*/] /* 2m+3 m-unsigned char blocks */) {
    //int sq = 0;
    unsigned char i, j, c;
    unsigned short checksum = 0;

    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // public key used as random nonce!!!
    absorb(hash, M, len); // followed by the message in this implementation (actually followed by the treetop key, and then by the message, in the full scheme)
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;

#ifdef DEBUG
    assert(10 <= m && m <= 127);
#endif

    // data part:
    for (i = 0; i < (unsigned char)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // lo part:
        memset(sig, 0, 16); sig[0] = (i << 1) + 0; // H(s, 2i + 0) // lo nybble tag
        AES_encrypt(sig, sig, (unsigned char *)s); // sig holds the private block s_{2i} for i-th "lo" nybble
        //sq++;
        c = h[i] & 15; // lo nybble
        checksum += 15 - (unsigned short)c;

#ifdef DEBUG
        assert(c < 16);
#endif

        for (j = 0; j < c; j++) {
            hash16(f, sig, sig);
            //sq++;
        }
        sig += 16; // signature block for next nybble

        // hi part:
        memset(sig, 0, 16); sig[0] = (i << 1) + 1; // H(s, 2i + 1) // hi nybble tag
        AES_encrypt(sig, sig, (unsigned char *)s); // sig holds the private block for i-th "hi" nybble
        //sq++;
        c = h[i] >>  4; // hi nybble
        checksum += 15 - (unsigned short)c;

#ifdef DEBUG
        assert(c < 16);
#endif
        for (j = 0; j < c; j++) {
            hash16(f, sig, sig);
            //sq++;
        }
        sig += 16; // signature block for next nybble
    }
    // checksum part:
    for (i = 0; i < 3; i++) { // checksum
        memset(sig, 0, 16); sig[0] = (m << 1) + i; // H(s, 2m + i) // lo nybble tag
        AES_encrypt(sig, sig, (unsigned char *)s); // sig holds the private block for i-th checksum nybble
        //sq++;
        c = checksum & 15; // least significant nybble
        checksum >>= 4;

#ifdef DEBUG
        assert(c < 16);
#endif
        for (j = 0; j < c; j++) {
            hash16(f, sig, sig);
            //sq++;
        }
        sig += 16; // signature block for next nybble
    }
    //printf("sig squeeze count: %d\n", sq);
    cleanup(hash);
}
#endif // WINTERNITZ_W = 4

#if WINTERNITZ_W == 8

/**
 * Sign H(v, M)under private key s, yielding (x_{0}, x_{1}, ..., x_{m-1})
 *
 * @param s the m-unsigned char private signing key.
 * @param v the corresponding m-unsigned char verification key, used here as the random nonce.
 * @param m hash length (sec level is 8*m).
 * @param M
 * @param len
 * @param priv
 * @param hash
 * @param h buffer for message hash
 * @param sig
 */
void winternitz_8_sign(const unsigned char s[/*m*/], const unsigned char v[/*m*/], const unsigned short m, const char *M, unsigned short len,
                       mmo_t *hash, dm_t *f, unsigned char h[/*m*/], unsigned char sig[/*(m+2)*m*/] /* m+2 m-unsigned char blocks */) {

    //int sq = 0;
    unsigned char i, j;
    unsigned short c, checksum = 0;
    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // public key used as random nonce!!!
    absorb(hash, M, len); // followed by the message in this implementation (actually followed by the treetop key, and then by the message, in the full scheme)
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;

#ifdef DEBUG
    assert(10 <= m && m <= 128);
#endif

    // data part:

    for (i = 0; i < (unsigned char)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // process 8-bit chunk
        memset(sig, 0, 16); sig[0] = i; // H(s, i) // byte tag
        AES_encrypt(sig, sig, (unsigned char *)s); // sig holds the private block i-th byte
        //sq++;
        checksum += 255 - (unsigned char)h[i];

#ifdef DEBUG
        assert(h[i] < 256);
#endif

        for (j = 0; j < (unsigned char)h[i]; j++) {
            hash16(f, sig, sig);  // sig holds the hash of its previous value
            //sq++;
        }
        sig += 16; // signature block for next nybble
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_CHECKSUM_SIZE; i++) {
        memset(sig, 0, 16); sig[0] = m + i; // H(s, m + i) // byte tag
        AES_encrypt(sig, sig, (unsigned char *)s); // sig holds the private block for i-th checksum unsigned char
        //sq++;
        c = checksum & 255; // least significant unsigned char
        checksum >>= 8;

#ifdef DEBUG
        assert(c < 256);
#endif

        for (j = 0; j < (unsigned char)c; j++) {
            hash16(f, sig, sig);  // sig holds the hash of its previous value
            //sq++;
        }
        sig += 16; // signature block for next unsigned char
    }
    //printf("sig squeeze count: %d\n", sq);
    cleanup(hash);
}
#endif /* WINTERNITZ_W = 8*/


void winternitz_sign(const unsigned char s[/*m*/], const unsigned char v[/*m*/], const unsigned short m, const char *M, unsigned short len,
                     mmo_t *hash, dm_t *f, unsigned char h[/*m*/], unsigned char sig[/*(m+2)*m*/] /* m+2 m-unsigned char blocks */) {

#if WINTERNITZ_W == 2
    winternitz_2_sign(s, v, m, M, len, hash, f, h, sig);
#elif WINTERNITZ_W == 4
    winternitz_4_sign(s, v, m, M, len, hash, f, h, sig);
#elif WINTERNITZ_W == 8
    winternitz_8_sign(s, v, m, M, len, hash, f, h, sig);
#endif
}

#if WINTERNITZ_W == 2
/**
 * Verify a signature on H(v, M)
 *
 * @param v the m-byte verification key, used here as the random nonce as well.
 * @param y
 * @param m
 * @param M
 * @param len
 * @param pubk
 * @param hash
 * @param h
 * @param y the signature
 * @param x scratch (should match v at the end)
 */
unsigned char winternitz_2_verify(const unsigned char v[/*m*/], const unsigned short m, const char *M, unsigned short len, mmo_t *hash, dm_t *f, unsigned char h[/*m*/], const unsigned char sig[/*(2*m+3)*m*/] /* 2m+3 m-byte blocks */, unsigned char x[/*m*/]) {
    //int sq = 0;
    unsigned char i, j, c;
    unsigned short checksum = 0;

#ifdef DEBUG
    assert(10 <= m && m <= 21); // lower bound: min sec level (80 bits), upper bound: max checksum count must fit one byte
#endif

    //*
    memset(h,2,m); //TODO: change this to a true hash
    /*/
    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m);   // random nonce!!!
    absorb(hash, M, len); // followed by the treetop key in the full scheme
    squeeze(hash, h, m);  // NB: digest length is m here, but was 2*m in the predecessor scheme
    //*/
    //sq++;

    // data part:
    sinit(hash, WINTERNITZ_SEC_LVL);

    for (i = 0; i < LEN_BYTES(WINTERNITZ_N); i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // 0 part:
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - ((h[i] >> 0) & 3); // chunk
        checksum += (unsigned short)c;
        for (j = 0; j < c; j++) {
              hash16(f, x, x); // x holds the hash of its previous value
            //sq++;
        }
        //absorb(hash, x, m);
        //memcpy(local_key,hash->H,16);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];

        sig += 16; // next signature block

        // 1 part:
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - ((h[i] >> 2) & 3); // chunk
        checksum += (unsigned short)c;
        for (j = 0; j < c; j++) {
              hash16(f, x, x); // x holds the hash of its previous value
            //sq++;
        }
        //absorb(hash, x, m);
        //memcpy(local_key,hash->H,16);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];

        sig += 16; // next signature block

        // 2 part:
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - ((h[i] >> 4) & 3); // chunk
        checksum += (unsigned short)c;
        for (j = 0; j < c; j++) {
              hash16(f, x, x); // x holds the hash of its previous value
            //sq++;
        }
        //absorb(hash, x, m);]
        //memcpy(local_key,hash->H,16);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];

        sig += 16; // next signature block

        // 3 part:
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - ((h[i] >> 6) & 3); // chunk
        checksum += (unsigned short)c;
        for (j = 0; j < c; j++) {
            hash16(f, x, x); // x holds the hash of its previous value
            //sq++;
        }
        //absorb(hash, x, m);
        //memcpy(local_key,hash->H,16);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];

        sig += 16; // next signature block

    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_l2; i++) { // checksum
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - (checksum & 3); // chunk
        checksum >>= 2;
        for (j = 0; j < c; j++) {
            hash16(f, x, x); // x holds the hash of its previous value
            //sq++;
        }
        //absorb(hash, x, m);
        //memcpy(local_key,hash->H,16);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];

        sig += 16; // next signature block
    }
    //squeeze(hash, x, m); // x should be the public key v
    memcpy(x, hash->H, 16);

    //sq++;
    //printf("ver squeeze count: %d\n", sq);
    cleanup(hash);
    return (memcmp(x, v, m) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
}
#endif // WINTERNITZ_W == 2

#if WINTERNITZ_W == 4

/**
 * Verify a signature on H(v, M)
 *
 * @param v the m-unsigned char verification key, used here as the random nonce as well.
 * @param y
 * @param m
 * @param M
 * @param len
 * @param pubk
 * @param hash
 * @param h
 * @param y the signature
 * @param x scratch (should match v at the end)
 */
unsigned char winternitz_4_verify(const unsigned char v[/*m*/], const unsigned short m, const char *M, unsigned short len, mmo_t *hash, dm_t *f, unsigned char h[/*m*/], const unsigned char *sig, unsigned char *x) {
    //int sq = 0;
    unsigned char i, j, c;
    unsigned short checksum = 0;

    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // random nonce!!!
    absorb(hash, M, len); // followed by the treetop key in the full scheme
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;

#ifdef DEBUG
    assert(10 <= m && m <= 127);
#endif

    // data part:
    sinit(hash, WINTERNITZ_SEC_LVL);

    for (i = 0; i < (unsigned char)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // lo part:
        memcpy(x, sig, m); // x holds now the i-th signature block
        c = 15 - (h[i] & 15); // lo nybble
        checksum += (unsigned short)c;

#ifdef DEBUG
        assert(c < 16);
#endif

        for (j = 0; j < c; j++) {
            hash16(f, x, x);  // x holds the hash of its previous value
            //sq++;
        }
        //absorb(pubk, x, m);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];
        sig += 16; // next signature block

        // hi part:
        memcpy(x, sig, m); // x is now the i-th signature block
        c = 15 - (h[i] >>  4); // hi nybble
        checksum += (unsigned short)c;

#ifdef DEBUG
        assert(c < 16);
#endif

        for (j = 0; j < c; j++) {
            hash16(f, x, x); // x is the hash of its previous value
            //sq++;
        }
        //absorb(hash, x, m);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];
        sig += 16; // next signature block
    }
    // checksum part:
    for (i = 0; i < 3; i++) { // checksum
        memcpy(x, sig, m); // x holds now the i-th signature block
        c = 15 - (checksum & 15); // least significant nybble
        checksum >>= 4;

#ifdef DEBUG
        assert(c < 16);
#endif

        for (j = 0; j < c; j++) {
            hash16(f, x, x);  // x holds the hash of its previous value
            //sq++;
        }
        //absorb(hash, x, m);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];
        sig += 16; // next signature block
    }
    //squeeze(hash, x, m); // x should be the public key v
    memcpy(x, hash->H, 16);
    //sq++;
    //printf("ver squeeze count: %d\n", sq);
    cleanup(hash);
    return (memcmp(x, v, m) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
}
#endif /* WINTERNITZ_W = 4*/

#if WINTERNITZ_W == 8

/**
 * Verify a signature on H(v, M)
 *
 * @param v the m-unsigned char verification key, used here as the random nonce as well.
 * @param y
 * @param m
 * @param M
 * @param len
 * @param pubk
 * @param hash
 * @param h
 * @param y the signature
 * @param x scratch (should match v at the end)
 */
unsigned char winternitz_8_verify(const unsigned char v[/*m*/], const unsigned short m, const char *M, unsigned short len, mmo_t *hash, dm_t *f, unsigned char h[/*m*/], const unsigned char sig[/*(m+2)*m*/] /* m+2 m-unsigned char blocks */, unsigned char x[/*m*/]) {
    //int sq = 0;
    unsigned char i, j;
    unsigned short c, checksum = 0;

    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // random nonce!!!
    absorb(hash, M, len); // followed by the treetop key in the full scheme
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;

#ifdef DEBUG
    assert(10 <= m && m <= 128);
#endif

    // data part:
    sinit(hash, WINTERNITZ_SEC_LVL);

    for (i = 0; i < (unsigned char)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // process unsigned char
        memcpy(x, sig, m); // x holds now the i-th signature block
        c = 255 - (unsigned char)h[i]; // unsigned char
        checksum += (unsigned char)c;

#ifdef DEBUG
        assert(c < 256);
#endif

        for (j = 0; j < (unsigned char)c; j++) {
            hash16(f, x, x);  // x holds the hash of its previous value
            //sq++;
        }
        //absorb(pubk, x, m);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];
        sig += 16; // next signature block
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_CHECKSUM_SIZE; i++) {
        memcpy(x, sig, m); // x holds now the i-th signature block
        c = 255 - (unsigned char)(checksum & 255); // least significant unsigned char
        checksum >>= 8;

#ifdef DEBUG
        assert(c < 256);
#endif

        for (j = 0; j < (unsigned char)c; j++) {
            hash16(f,x,x);  // x holds the hash of its previous value
            //sq++;
        }
        //absorb(pubk, x, m);
        AES_encrypt(hash->H, x, hash->H);
        hash->H[ 0] ^= x[ 0];
        hash->H[ 1] ^= x[ 1];
        hash->H[ 2] ^= x[ 2];
        hash->H[ 3] ^= x[ 3];
        hash->H[ 4] ^= x[ 4];
        hash->H[ 5] ^= x[ 5];
        hash->H[ 6] ^= x[ 6];
        hash->H[ 7] ^= x[ 7];
        hash->H[ 8] ^= x[ 8];
        hash->H[ 9] ^= x[ 9];
        hash->H[10] ^= x[10];
        hash->H[11] ^= x[11];
        hash->H[12] ^= x[12];
        hash->H[13] ^= x[13];
        hash->H[14] ^= x[14];
        hash->H[15] ^= x[15];
        sig += 16; // next signature block
    }
    //squeeze(pubk, x, m); // x should be the public key v
    memcpy(x, hash->H, 16);
    //sq++;
    //printf("ver squeeze count: %d\n", sq);
    cleanup(hash);
    return (memcmp(x, v, m) == 0 ? WINTERNITZ_OK : WINTERNITZ_ERROR);
}
#endif /*WINTERNITZ_W = 8*/

unsigned char winternitz_verify(const unsigned char v[], const unsigned short m, const char *M, unsigned short len, mmo_t *hash,
                                dm_t *f, unsigned char h[], const unsigned char sig[], unsigned char *x) {
#if WINTERNITZ_W == 2
    return winternitz_2_verify(v, m, M, len, hash, f, h, sig, x);
#elif WINTERNITZ_W == 4
    return winternitz_4_verify(v, m, M, len, hash, f, h, sig, x);
#elif WINTERNITZ_W == 8
    return winternitz_8_verify(v, m, M, len, hash, f, h, sig, x);
#endif
    return WINTERNITZ_ERROR;
}

/*
\begin{itemize}
\item \textsf{Gen}:
Choose $s \samples \{0 \dots 2^w-1\}^\ell$ uniformly at random,
compute the $\ell \cdot 2^h$ strings $s_i^{(j)} \gets H(s \mid\mid i \mid\mid j)$ and correspondingly the $\ell \cdot 2^h$ strings $v_i^{(j)} \gets H^{2^w-1}(s_i^{(j)})$,
compute  $v^{(j)} \gets H(v_0^{(j)} \mid\mid \dots \mid\mid v_{\ell-1}^{(j)})$,
compute the Merkle tree nodes $q_u = H(q_{2u} \mid\mid q_{2u+1})$ for $1 \leqslant u < 2^h$, and $q_{2^h + j} = H(v^{(j)})$ for $0 \leqslant i < \ell$, $0 \leqslant j < 2^h$.
The private key is $s$, and the public key is $Y := q_1$, each consisting of $\ell$ $w$-bit words\footnote{The BDS algorithm, if adopted, would compute some ancillary information to expedite signing as well.}. The $s_i^{(j)}$ and $v^{(j)}$ keys as well as the authentication path can be recomputed on demand during a signing operation.
%
\item \textsf{Sig}:
To sign the $j$-th message $M^{(j)}$, compute the message representative $m^{(j)} := (m_0^{(j)}, \dots, m_{\ell-1}^{(j)}) \gets G(Y, v^{(j)}, M^{(j)})$,
compute $s_i^{(j)} \gets H(s \mid\mid i \mid\mid j)$ and $S_i^{(j)} \gets H^{2^w - 1 - m_i}(s_i^{(j)})$ for $0 \leqslant i < \ell$,
compute $S^{(j)} \gets (S_0^{(j)}, \dots, S_{\ell-1}^{(j)})$ and the authentication path $Q^{(j)} := (q_{\lfloor j/2^u \rfloor \oplus 1} \mid u = 0, \dots, h-1)$,
and finally let the signature be the triple $(S^{(j)}, v^{(j)}, Q^{(j)})$.
%
\item \textsf{Ver}:
To verify a signature $(S^{(j)}, v^{(j)}, Q^{(j)})$ for the $j$-th message $M^{(j)}$,
compute the message representative $m^{(j)} := (m_0^{(j)}, \dots, m_{\ell-1}^{(j)}) \gets G(Y, v^{(j)}, M^{(j)})$,
compute $t_i^{(j)} = H^{m_i^{(j)}}(S_i^{(j)})$ for $0 \leqslant i < \ell$ and $t^{(j)} \gets H(t_0^{(j)} \mid\mid \dots \mid\mid t_{\ell-1}^{(j)})$.
Then compute the nodes from the $j$-th leaf to the root via $q_{2^h + j} = H(v^{(j)})$ and $q_i \gets H(q_{2i} \mid\mid q_{2i+1})$ for $1 \leqslant i < 2^h$,
taking the missing nodes from the authentication path $Q^{(j)}$. Accept iff $q_1 = Y$ and $v^{(j)} = t^{(j)}$.
\end{itemize}
*/

#if defined(WINTERNITZ_SELFTEST)

int main(int argc, char *argv[]) {

    unsigned char m = LEN_BYTES(WINTERNITZ_SEC_LVL);
    sponge_t hash;
    unsigned char s[m]; // the m-unsigned char private signing key.
    unsigned char v[m]; // the corresponding m-unsigned char verification key.
    char M[] = "Hello, world!";
    unsigned char h[m]; // m-unsigned char message hash.
    unsigned char sig[WINTERNITZ_L*m];
    unsigned char x[m]; // scratch (should match v at the end)
    unsigned char ok;
    unsigned char i;
    clock_t elapsed;
    int test, tests = 10;

    printf("\n Winternitz(w = %d, sec = %d) \n\n", WINTERNITZ_W, WINTERNITZ_SEC_LVL);
    printf("l1 = %d, checksum = %d, L = %d \n\n", WINTERNITZ_l1, WINTERNITZ_CHECKSUM_SIZE, WINTERNITZ_L);
    printf("mem occupation: %d unsigned chars.\n",
        sizeof(priv) + sizeof(hash) + sizeof(pubk) + sizeof(s) + sizeof(v) + sizeof(M) + sizeof(h) + sizeof(sig) + sizeof(x));
    printf("sig size: %d unsigned chars.\n\n", sizeof(sig));

    for (i = 0; i < m; i++) {
        s[i] = 0xA0 ^ i; // sample private key, for debugging only
    }

    printf("======== GEN ========\n");
    elapsed = -clock();
    //display("priv", s, m);
    for (test = 0; test < tests; test++) {
        winternitz_keygen(s, m, &hash, v);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    //display("pubk", v, m);

    printf("======== SIG ========\n");
    elapsed = -clock();
     for (test = 0; test < tests; test++) {
        winternitz_sign(s, v, m, (const unsigned char *)M, strlen(M)+1, &hash, h, sig);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    //display("wsig", sig, 2*m*m);

    printf("======== VER ========\n");
    elapsed = -clock();
     for (test = 0; test < tests; test++) {
        ok = winternitz_verify(v, m, (const unsigned char *)M, strlen(M)+1, &hash, h, sig, x);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    printf("**** verification ok? >>>> %s <<<<\n", ok ? "true" : "false");
    //display("verv", x, m);
    return 0;
}
#endif
