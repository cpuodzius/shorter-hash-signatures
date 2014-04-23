#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sponge.h"

#ifdef __PIC__wee
#define assert(c)
#endif // __PIC__wee

/**
 * Compute a Winternitz public key v = H_m(x_{0:0}^3, x_{0:1}^3, x_{0:2}^3, x_{0:3}^3, ..., x_{(L-1):0}^3, x_{(L-1):1}^3, x_{(L-1):2}^3, x_{(L-1):3}^3), with L = m + ceil(lg(3*4*m)/8).
 *
 * @param s         the m-byte private signing key.
 * @param m         hash length in bytes (sec level is 8*m).
 * @param v         the corresponding m-byte verification key.
 * @param priv
 * @param hash
 * @param pubk
 * @param v
 */
void winternitz2Gen(const byte s[/*m*/], const uint m, sponge_t *priv, sponge_t *hash, sponge_t *pubk, byte v[/*m*/]) {
    //int sq = 0;
    byte i, j;
    uint seclevel = m << 3;
    // NB: for 1 <= m <= 21 (hence, sec level up to 2^168), the value of ceil(lg(3*4*m)/8) is simply 1 byte.
    byte L = 4*(byte)(m + 1); // chunk count, including checksum
    assert(10 <= m && m <= 21); // lower bound: min sec level (80 bits), upper bound: max checksum count must fit one byte

    sinit(priv, seclevel);
    sinit(pubk, seclevel);
    for (i = 0; i < L; i++) { // scan over the 2-bit chunks:
        absorb(priv, s, m); // H(s, ...) master signing key
        absorb(priv, &i, 1); // H(s, i) // i = chunk index
        squeeze(priv, v, m); // v = s_i = private key block for i-th chunk
        //sq++;
        for (j = 0; j < 3; j++) {
            sinit(hash, seclevel);
            absorb(hash, v, m);
            squeeze(hash, v, m); // v is the hash of its previous value = y_i = H^3(s_i)
            //sq++;
        }
        absorb(pubk, v, m);  // s_0 || ... || s_i ...
    }
    squeeze(pubk, v, m); // v is finally the public key, v = H(s_0 || s_1 || ... || s_{L-1})
    //sq++;
    //printf("gen squeeze count: %d\n", sq);
    cleanup(priv);
    cleanup(hash);
    cleanup(pubk);
}

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
void winternitz2Sig(const byte s[/*m*/], const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *priv, sponge_t *hash, byte h[/*m*/], byte sig[/*4*(m+1)*m*/] /* 4*(m+1) m-byte blocks */) {
    //int sq = 0;
    byte i, c;
    uint seclevel = m << 3;
    uint checksum = 0;
    sinit(hash, seclevel);
    absorb(hash, v, m); // public key used as random nonce!!!
    absorb(hash, M, len); // followed by the message in this implementation (actually followed by the treetop key, and then by the message, in the full scheme)
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;
    // data part:
    sinit(priv, seclevel);
    assert(10 <= m && m <= 21); // lower bound: min sec level (80 bits), upper bound: max checksum count must fit one byte
    for (i = 0; i < (byte)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // 0 part:
        absorb(priv, s, m); // H(s, ...)
        c = (i << 2) + 0; absorb(priv, &c, 1); // H(s, 4i + 0) // 0 chunk index
        squeeze(priv, sig, m); // sig holds the private block for i-th "0" chunk
        //sq++;
        checksum += 3;
        switch ((h[i]     ) & 3) { // 0 chunk
        case 3:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 2:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 1:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        sig += m; // signature block for next chunk

        // 1 part:
        absorb(priv, s, m); // H(s, ...)
        c = (i << 2) + 1; absorb(priv, &c, 1); // H(s, 4i + 1) // 1 chunk index
        squeeze(priv, sig, m); // sig holds the private block for i-th "1" chunk
        //sq++;
        checksum += 3;
        switch ((h[i] >> 2) & 3) { // 1 chunk
        case 3:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 2:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 1:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        sig += m; // signature block for next chunk

        // 2 part:
        absorb(priv, s, m); // H(s, ...)
        c = (i << 2) + 2; absorb(priv, &c, 1); // H(s, 4i + 2) // 2 chunk index
        squeeze(priv, sig, m); // sig holds the private block for i-th "2" chunk
        //sq++;
        checksum += 3;
        switch ((h[i] >> 4) & 3) { // 2 chunk
        case 3:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 2:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 1:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        sig += m; // signature block for next chunk

        // 3 part:
        absorb(priv, s, m); // H(s, ...)
        c = (i << 2) + 3; absorb(priv, &c, 1); // H(s, 4i + 3) // 3 chunk index
        squeeze(priv, sig, m); // sig holds the private block for i-th "3" chunk
        //sq++;
        checksum += 3;
        switch ((h[i] >> 6) & 3) { // 3 chunk
        case 3:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 2:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 1:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            checksum--; // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        sig += m; // signature block for next chunk

    }
    // checksum part:
    for (i = 0; i < 4; i++) { // checksum
        absorb(priv, s, m); // H(s, ...)
        c = (m << 2) + i; absorb(priv, &c, 1); // H(s, 4m + i) // i-th chunk index
        squeeze(priv, sig, m); // sig holds the private block for i-th checksum chunk
        //sq++;
        switch (checksum & 3) { // 3 chunk
        case 3:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            // FALLTHROUGH
        case 2:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            // FALLTHROUGH
        case 1:
            sinit(hash, seclevel);
            absorb(hash, sig, m);
            squeeze(hash, sig, m); // sig holds the hash of its previous value
            //sq++;
            // FALLTHROUGH
        case 0:
            ;
            // FALLTHROUGH
        }
        checksum >>= 2;
        sig += m; // signature block for next nybble
    }
    //printf("sig squeeze count: %d\n", sq);
    cleanup(priv);
    cleanup(hash);
}

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
bool winternitz2Ver(const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *pubk, sponge_t *hash, byte h[/*m*/], const byte sig[/*(2*m+3)*m*/] /* 2m+3 m-byte blocks */, byte x[/*m*/]) {
    //int sq = 0;
    byte i, j, c;
    uint seclevel = m << 3;
    uint checksum = 0;
    bool ok;
    sinit(hash, seclevel);
    absorb(hash, v, m); // random nonce!!!
    absorb(hash, M, len); // followed by the treetop key in the full scheme
    squeeze(hash, h, m); // NB: hash length is m here, but was 2*m in the predecessor scheme
    //sq++;
    // data part:
    sinit(pubk, seclevel);
    assert(10 <= m && m <= 21); // lower bound: min sec level (80 bits), upper bound: max checksum count must fit one byte
    for (i = 0; i < (byte)m; i++) { // NB: hash length is m here, but was 2*m in the predecessor scheme
        // 0 part:
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - ((h[i] >> 0) & 3); // chunk
        checksum += (uint)c;
        for (j = 0; j < c; j++) {
            sinit(hash, seclevel);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x holds the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block

        // 1 part:
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - ((h[i] >> 2) & 3); // chunk
        checksum += (uint)c;
        for (j = 0; j < c; j++) {
            sinit(hash, seclevel);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x holds the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block

        // 2 part:
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - ((h[i] >> 4) & 3); // chunk
        checksum += (uint)c;
        for (j = 0; j < c; j++) {
            sinit(hash, seclevel);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x holds the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block

        // 3 part:
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - ((h[i] >> 6) & 3); // chunk
        checksum += (uint)c;
        for (j = 0; j < c; j++) {
            sinit(hash, seclevel);
            absorb(hash, x, m);
            squeeze(hash, x, m); // x holds the hash of its previous value
            //sq++;
        }
        absorb(pubk, x, m);
        sig += m; // next signature block

    }
    // checksum part:
    for (i = 0; i < 4; i++) { // checksum
        memcpy(x, sig, m); // x holds now the current signature block
        c = 3 - (checksum & 3); // chunk
        checksum >>= 2;
        for (j = 0; j < c; j++) {
            sinit(hash, seclevel);
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

void display(const char *tag, const byte *u, uint n) {
    uint i;
    printf("%s:\n", tag);
    for (i = 0; i < n; i++) {
        printf("%02X", u[i]);
    }
    printf("\n\n");
}

int main(int argc, char *argv[]) {
    uint seclevel = 128, m = seclevel >> 3;
    sponge_t priv, hash, pubk;
    byte s[m]; // the m-byte private signing key.
    byte v[m]; // the corresponding m-byte verification key.
    char M[] = "Hello, world!";
    byte h[m]; // m-byte message hash.
    byte sig[4*(m + 1)*m];
    byte x[m]; // scratch (should match v at the end)
    bool ok;
    byte i;
    clock_t elapsed;
    int test, tests = 10000;

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
        winternitz2Gen(s, m, &priv, &hash, &pubk, v);
    }
    elapsed += clock();
    printf("GEN time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    //display("pubk", v, m);

    printf("======== SIG ========\n");
    elapsed = -clock();
     for (test = 0; test < tests; test++) {
        winternitz2Sig(s, v, m, (const byte *)M, strlen(M)+1, &priv, &hash, h, sig);
    }
    elapsed += clock();
    printf("SIG time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    //display("wsig", sig, 2*m*m);

    printf("======== VER ========\n");
    elapsed = -clock();
     for (test = 0; test < tests; test++) {
        ok = winternitz2Ver(v, m, (const byte *)M, strlen(M)+1, &pubk, &hash, h, sig, x);
    }
    elapsed += clock();
    printf("VER time: %.1f us\n", 1000000*(float)elapsed/CLOCKS_PER_SEC/tests);
    printf("**** verification ok? >>>> %s <<<<\n", ok ? "true" : "false");
    //display("verv", x, m);
    return 0;
}
