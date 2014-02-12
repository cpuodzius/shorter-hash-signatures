#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sponge.h"
#include "winternitz.h"

#ifdef __PIC__wee
#define assert(c)
#endif // __PIC__wee

#if WINTERNITZ_W == 2

/**
 * Compute a Winternitz public key v = H_m(x_{0:sn0}^3, x_{0:sn1}^3, x_{0:sn2}^3, x_{0:sn3}^3 ..., x_{(L-1):sn0}^3, x_{(L-1):sn1}^3, x_{(L-1):sn2}^3, x_{(L-1):sn3}^3), with L = 4*m + ceil(lg(3*4*m)/8).
 *
 * @param s         the m-byte private signing key.
 * @param m         hash length (sec level is 8*m).
 * @param v         the corresponding m-byte verification key.
 * @param priv
 * @param hash
 * @param pubk
 * @param v
 */
void winternitz2Gen(const byte s[/*m*/], const uint m, sponge_t *priv, sponge_t *hash, sponge_t *pubk, byte v[/*m*/]) {
    //int sq = 0;
    byte i, j;

    byte L = 4*(byte)m + 4; // semi-nybble (sn) count, including checksum

    sinit(priv, WINTERNITZ_SEC_LVL);
    sinit(pubk, WINTERNITZ_SEC_LVL);
    for (i = 0; i < L; i++) {
        absorb(priv, s, m); // H(s, ...)
        absorb(priv, &i, 1); // H(s, i) // i = nybble tag
        squeeze(priv, v, m); // v = s_i = private block for i-th nybble
        //sq++;
        for (j = 0; j < 3; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, v, m);
            squeeze(hash, v, m); // v is the hash of its previous value = y_i = H^3(s_i)
            //sq++;
        }
        absorb(pubk, v, m);  // y_0 || ... || y_i ...
    }
    squeeze(pubk, v, m); // v is finally the public key, v = H(y_0 || y_1 || ... || y_{L-1})
    //sq++;
    //printf("gen squeeze count: %d\n", sq);
    cleanup(priv);
    cleanup(hash);
    cleanup(pubk);
}
#endif // WINTERNITZ_W = 2

#if WINTERNITZ_W == 4

/**
 * Compute a Winternitz public key v = H_m(x_{0:lo}^15, x_{0:hi}^15, ..., x_{(L-1):lo}^15, x_{(L-1):hi}^15), with L = m + ceil(lg(15*2*m)/8).
 *
 * @param s         the m-byte private signing key.
 * @param m         hash length (sec level is 8*m).
 * @param v         the corresponding m-byte verification key.
 * @param priv
 * @param hash
 * @param pubk
 * @param v
 */
void winternitz4Gen(const byte s[/*m*/], const uint m, sponge_t *priv, sponge_t *hash, sponge_t *pubk, byte v[/*m*/]) {
    //int sq = 0;
    byte i, j;
    // NB: for 9 <= m <= 136, the value of ceil(lg(15*2*m)/8) is simply 3 nybbles.
    byte L = 2*(byte)m + 3; // nybble count, including checksum
    assert(10 <= m && m <= 127); // lower bound: min sec level (80 bits), upper bound: max nybble count 2*(m-1)+3 must fit one byte

    sinit(priv, WINTERNITZ_SEC_LVL);
    sinit(pubk, WINTERNITZ_SEC_LVL);
    for (i = 0; i < L; i++) {
        absorb(priv, s, m); // H(s, ...)
        absorb(priv, &i, 1); // H(s, i) // i = nybble tag
        squeeze(priv, v, m); // v = s_i = private block for i-th nybble
        //sq++;
        for (j = 0; j < 15; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, v, m);
            squeeze(hash, v, m); // v is the hash of its previous value = y_i = H^15(s_i)
            //sq++;
        }
        absorb(pubk, v, m);  // y_0 || ... || y_i ...
    }
    squeeze(pubk, v, m); // v is finally the public key, v = H(y_0 || y_1 || ... || y_{L-1})
    //sq++;
    //printf("gen squeeze count: %d\n", sq);
    cleanup(priv);
    cleanup(hash);
    cleanup(pubk);
}
#endif // WINTERNITZ_W = 4


#if WINTERNITZ_W == 8

/**
 * Compute a Winternitz public key v = H_m(x_{0}^255, x_{1}^255, ..., x_{L-1}^255), with L = m + ceil(lg(255*m)/8), m = seclevel/8.
 *
 * @param s         the m-byte private signing key.
 * @param m         hash length (sec level is 8*m).
 * @param v         the corresponding m-byte verification key.
 * @param priv
 * @param hash
 * @param pubk
 * @param v
 */
void winternitz8Gen(const byte s[/*m*/], const uint m, sponge_t *priv, sponge_t *hash, sponge_t *pubk, byte v[/*m*/]) {
    //int sq = 0;
    byte i, j;
    // NB: for 2 <= m <= 257, the value of ceil(lg(255*m)/8) is simply 2 bytes.
    assert(10 <= m && m <= 127); // lower bound: min sec level (80 bits), upper bound: max byte count

    sinit(priv, WINTERNITZ_SEC_LVL);
    sinit(pubk, WINTERNITZ_SEC_LVL);
    for (i = 0; i < WINTERNITZ_L; i++) { // byte count, including checksum
        absorb(priv, s, m); // H(s, ...)
        absorb(priv, &i, 1); // H(s, i) // i = byte tag
        squeeze(priv, v, m); // v = s_i = private block for i-th byte
        //sq++;
        for (j = 0; j < 255; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, v, m);
            squeeze(hash, v, m); // v is the hash of its previous value = y_i = H^255(s_i)
            //sq++;
        }
        absorb(pubk, v, m);  // y_0 || ... || y_i ...
    }
    squeeze(pubk, v, m); // v is finally the public key, v = H(y_0 || y_1 || ... || y_{L-1})
    //sq++;
    //printf("gen squeeze count: %d\n", sq);
    cleanup(priv);
    cleanup(hash);
    cleanup(pubk);
}
#endif // WINTERNITZ_W = 8

void winternitzGen(const byte s[/*m*/], const uint m, sponge_t *priv, sponge_t *hash, sponge_t *pubk, byte v[/*m*/]) {

#if WINTERNITZ_W == 2
    winternitz2Gen(s, m, priv, hash, pubk, v);
#elif WINTERNITZ_W == 4
    winternitz4Gen(s, m, priv, hash, pubk, v);
#elif WINTERNITZ_W == 8
    winternitz8Gen(s, m, priv, hash, pubk, v);
#endif
}


#if WINTERNITZ_W == 4

/**
 * Sign H(v, M)under private key s, yielding (x_{0:lo}, x_{0:hi}, ..., x_{(m-1):lo}, x_{(m-1):hi})
 *
 * @param s the m-byte private signing key.
 * @param v the corresponding m-byte verification key, used here as the random nonce.
 * @param m hash length (sec level is 8*m).
 * @param M
 * @param len
 * @param priv
 * @param hash
 * @param h buffer for message hash
 * @param sig
 */
void winternitz4Sig(const byte s[/*m*/], const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *priv, sponge_t *hash, byte h[/*m*/], byte sig[/*(2*m+3)*m*/] /* 2m+3 m-byte blocks */) {
    //int sq = 0;
    byte i, j, c;
    uint checksum = 0;
    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // public key used as random nonce!!!
    absorb(hash, M, len); // followed by the message in this implementation (actually followed by the treetop key, and then by the message, in the full scheme)
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;
    // data part:
    sinit(priv, WINTERNITZ_SEC_LVL);
    assert(10 <= m && m <= 127);
    for (i = 0; i < (byte)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // lo part:
        absorb(priv, s, m); // H(s, ...)
        c = (i << 1) + 0; absorb(priv, &c, 1); // H(s, 2i + 0) // lo nybble tag
        squeeze(priv, sig, m); // sig holds the private block s_{2i} for i-th "lo" nybble
        //sq++;
        c = h[i] & 15; // lo nybble
        checksum += 15 - (uint)c;
        assert(c < 16);
        for (j = 0; j < c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
        }
        sig += m; // signature block for next nybble

        // hi part:
        absorb(priv, s, m); // H(s, ...)
        c = (i << 1) + 1; absorb(priv, &c, 1); // H(s, 2i + 1) // hi nybble tag
        squeeze(priv, sig, m); // sig holds the private block for i-th "hi" nybble
        //sq++;
        c = h[i] >>  4; // hi nybble
        checksum += 15 - (uint)c;
        assert(c < 16);
        for (j = 0; j < c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
        }
        sig += m; // signature block for next nybble
    }
    // checksum part:
    for (i = 0; i < 3; i++) { // checksum
        absorb(priv, s, m); // H(s, ...)
        c = (m << 1) + i; absorb(priv, &c, 1); // H(s, 2m + i) // lo nybble tag
        squeeze(priv, sig, m); // sig holds the private block for i-th checksum nybble
        //sq++;
        c = checksum & 15; // least significant nybble
        checksum >>= 4;
        assert(c < 16);
        for (j = 0; j < c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
        }
        sig += m; // signature block for next nybble
    }
    //printf("sig squeeze count: %d\n", sq);
    cleanup(priv);
    cleanup(hash);
}
#endif /* WINTERNITZ_W = 4 */

#if WINTERNITZ_W == 8

/**
 * Sign H(v, M)under private key s, yielding (x_{0}, x_{1}, ..., x_{m-1})
 *
 * @param s the m-byte private signing key.
 * @param v the corresponding m-byte verification key, used here as the random nonce.
 * @param m hash length (sec level is 8*m).
 * @param M
 * @param len
 * @param priv
 * @param hash
 * @param h buffer for message hash
 * @param sig
 */
void winternitz8Sig(const byte s[/*m*/], const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *priv, sponge_t *hash, byte h[/*m*/], byte sig[/*(m+2)*m*/] /* m+2 m-byte blocks */) {

    //int sq = 0;
    byte i, j;
    uint c, checksum = 0;
    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // public key used as random nonce!!!
    absorb(hash, M, len); // followed by the message in this implementation (actually followed by the treetop key, and then by the message, in the full scheme)
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;
    // data part:
    sinit(priv, WINTERNITZ_SEC_LVL);
    assert(10 <= m && m <= 128);
    for (i = 0; i < (byte)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // process byte
        absorb(priv, s, m); // H(s, ...)
        absorb(priv, &i, 1); // H(s, i) // byte tag
        squeeze(priv, sig, m); // sig holds the private block i-th byte
        //sq++;
        checksum += 255 - (byte)h[i];
        assert(h[i] < 256);
        for (j = 0; j < (byte)h[i]; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
        }
        sig += m; // signature block for next nybble
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_CHECKSUM_SIZE; i++) {
        absorb(priv, s, m); // H(s, ...)
        c = m + i; absorb(priv, &c, 1); // H(s, m + i) // byte tag
        squeeze(priv, sig, m); // sig holds the private block for i-th checksum byte
        //sq++;
        c = checksum & 255; // least significant byte
        checksum >>= 8;
        assert(c < 256);
        for (j = 0; j < (byte)c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
        }
        sig += m; // signature block for next byte
    }
    //printf("sig squeeze count: %d\n", sq);
    cleanup(priv);
    cleanup(hash);
}
#endif /* WINTERNITZ_W = 8*/


void winternitzSig(const byte s[/*m*/], const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *priv, sponge_t *hash, byte h[/*m*/], byte sig[/*(m+2)*m*/] /* m+2 m-byte blocks */) {
#if WINTERNITZ_W == 4
    winternitz4Sig(s, v, m, M, len, priv, hash, h, sig);
#elif WINTERNITZ_W == 8
    winternitz8Sig(s, v, m, M, len, priv, hash, h, sig);
#endif
}

#if WINTERNITZ_W == 4

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
bool winternitz4Ver(const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *pubk, sponge_t *hash, byte h[/*m*/], const byte sig[/*(2*m+3)*m*/] /* 2m+3 m-byte blocks */, byte x[/*m*/]) {
    //int sq = 0;
    byte i, j, c;
    uint checksum = 0;
    bool ok;
    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // random nonce!!!
    absorb(hash, M, len); // followed by the treetop key in the full scheme
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;
    // data part:
    sinit(pubk, WINTERNITZ_SEC_LVL);
    assert(10 <= m && m <= 127);
    for (i = 0; i < (byte)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // lo part:
        memcpy(x, sig, m); // x holds now the i-th signature block
        c = 15 - (h[i] & 15); // lo nybble
        checksum += (uint)c;
        assert(c < 16);
        for (j = 0; j < c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x holds the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block

        // hi part:
        memcpy(x, sig, m); // x is now the i-th signature block
        c = 15 - (h[i] >>  4); // hi nybble
        checksum += (uint)c;
        assert(c < 16);
        for (j = 0; j < c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x is the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block
    }
    // checksum part:
    for (i = 0; i < 3; i++) { // checksum
        memcpy(x, sig, m); // x holds now the i-th signature block
        c = 15 - (checksum & 15); // least significant nybble
        checksum >>= 4;
        assert(c < 16);
        for (j = 0; j < c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x holds the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block
    }
    squeeze(pubk, x, m); // x should be the public key v
    //sq++;
    //printf("ver squeeze count: %d\n", sq);
    ok = (memcmp(x, v, m) == 0);
    cleanup(pubk);
    cleanup(hash);
    return ok;
}
#endif /* WINTERNITZ_W = 4*/

#if WINTERNITZ_W == 8

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
bool winternitz8Ver(const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *pubk, sponge_t *hash, byte h[/*m*/], const byte sig[/*(m+2)*m*/] /* m+2 m-byte blocks */, byte x[/*m*/]) {
    //int sq = 0;
    byte i, j;
    uint c, checksum = 0;
    bool ok;
    sinit(hash, WINTERNITZ_SEC_LVL);
    absorb(hash, v, m); // random nonce!!!
    absorb(hash, M, len); // followed by the treetop key in the full scheme
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;
    // data part:
    sinit(pubk, WINTERNITZ_SEC_LVL);
    assert(10 <= m && m <= 128);
    for (i = 0; i < (byte)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // process byte
        memcpy(x, sig, m); // x holds now the i-th signature block
        c = 255 - (byte)h[i]; // byte
        checksum += (byte)c;
        assert(c < 256);
        for (j = 0; j < (byte)c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x holds the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block
    }
    // checksum part:
    for (i = 0; i < WINTERNITZ_CHECKSUM_SIZE; i++) {
        memcpy(x, sig, m); // x holds now the i-th signature block
        c = 255 - (byte)(checksum & 255); // least significant byte
        checksum >>= 8;
        assert(c < 256);
        for (j = 0; j < (byte)c; j++) {
            sinit(hash, WINTERNITZ_SEC_LVL);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x holds the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block
    }
    squeeze(pubk, x, m); // x should be the public key v
    //sq++;
    //printf("ver squeeze count: %d\n", sq);
    ok = (memcmp(x, v, m) == 0);
    cleanup(pubk);
    cleanup(hash);
    return ok;
}
#endif /*WINTERNITZ_W = 8*/

bool winternitzVer(const byte v[], const uint m, const byte *M, uint len, sponge_t *pubk, sponge_t *hash, byte h[], const byte sig[], byte x[]) {
#if WINTERNITZ_W == 4
    return winternitz4Ver(v, m, M, len, pubk, hash, h, sig, x);
#elif WINTERNITZ_W == 8
    return winternitz8Ver(v, m, M, len, pubk, hash, h, sig, x);
#endif
    return ERROR;
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
    sponge_t priv, hash, pubk;
    byte s[m]; // the m-byte private signing key.
    byte v[m]; // the corresponding m-byte verification key.
    char M[] = "Hello, world!";
    byte h[m]; // m-byte message hash.
    byte sig[WINTERNITZ_L*m];
    byte x[m]; // scratch (should match v at the end)
    bool ok;
    byte i;
    clock_t elapsed;
    int test, tests = 10;

    printf("\n Winternitz(w = %d, sec = %d) \n\n", WINTERNITZ_W, WINTERNITZ_SEC_LVL);
    printf("l1 = %d, checksum = %d, L = %d \n\n", WINTERNITZ_l1, WINTERNITZ_CHECKSUM_SIZE, WINTERNITZ_L);
    printf("mem occupation: %d bytes.\n",
        sizeof(priv) + sizeof(hash) + sizeof(pubk) + sizeof(s) + sizeof(v) + sizeof(M) + sizeof(h) + sizeof(sig) + sizeof(x));
    printf("sig size: %d bytes.\n\n", sizeof(sig));

    for (i = 0; i < m; i++) {
        s[i] = 0xA0 ^ i; // sample private key, for debugging only
    }

    printf("======== GEN ========\n");
    elapsed = -clock();
    //display("priv", s, m);
    for (test = 0; test < tests; test++) {
        winternitzGen(s, m, &priv, &hash, &pubk, v);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    //display("pubk", v, m);

    printf("======== SIG ========\n");
    elapsed = -clock();
     for (test = 0; test < tests; test++) {
        winternitzSig(s, v, m, (const byte *)M, strlen(M)+1, &priv, &hash, h, sig);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    //display("wsig", sig, 2*m*m);

    printf("======== VER ========\n");
    elapsed = -clock();
     for (test = 0; test < tests; test++) {
        ok = winternitzVer(v, m, (const byte *)M, strlen(M)+1, &pubk, &hash, h, sig, x);
    }
    elapsed += clock();
    printf("Elapsed time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    printf("**** verification ok? >>>> %s <<<<\n", ok ? "true" : "false");
    //display("verv", x, m);
    return 0;
}
#endif
