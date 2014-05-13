#ifndef __MSS_H
#define __MSS_H

#include "winternitz.h"

// Improved Merkle Signature Scheme targeting 16-bit platforms
// 16 is the Heighest tree for this implementation (since leaf index is of type short)

#define MSS_OK 1
#define MSS_ERROR 0

#define odd(x)	((x) % 2)

#define MSS_SEC_LVL                     WINTERNITZ_SEC_LVL
#define MSS_HEIGHT			5
#define MSS_K				3

#if odd(MSS_HEIGHT - MSS_K)
#error (H - K) must be even
#endif

#define MSS_TREEHASH_SIZE		MSS_HEIGHT - MSS_K
#define MSS_STACK_SIZE			MSS_HEIGHT - MSS_K - 2
#define MSS_KEEP_SIZE			MSS_HEIGHT // Keep is used as stack during key generation
#define MSS_RETAIN_SIZE			(1 << MSS_K) - MSS_K - 1

#define NODE_VALUE_SIZE LEN_BYTES(MSS_SEC_LVL)         // each value element is a byte

struct mss_node {
        unsigned char height;
        short index;
        unsigned char value[NODE_VALUE_SIZE];           // node's value for auth path
};

//treehash_seed: index of the seed for the treehash of height h
struct state_mt {
	unsigned char treehash_state[MSS_TREEHASH_SIZE], treehash_used[MSS_TREEHASH_SIZE];
	short stack_index, retain_index[MSS_K-1], treehash_seed[MSS_TREEHASH_SIZE];
        struct mss_node treehash[MSS_TREEHASH_SIZE];
        struct mss_node stack[MSS_STACK_SIZE];
        struct mss_node retain[MSS_RETAIN_SIZE];
        struct mss_node keep[MSS_KEEP_SIZE];
        struct mss_node auth[MSS_HEIGHT];
		struct mss_node store[MSS_TREEHASH_SIZE-1];
};

void mss_keygen(dm_t *hash, sponge_t *pubk, unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], struct mss_node *node1, struct mss_node *node2, struct state_mt *state, unsigned char pkey[NODE_VALUE_SIZE]);

void mss_sign(struct state_mt *state, unsigned char *seed, struct mss_node *leaf, const char *M, short len,
              sponge_t *hash, sponge_t *pubk, dm_t *f, unsigned char *h, short leaf_index, struct mss_node *node1, struct mss_node *node2,
              unsigned char *sig, struct mss_node authpath[MSS_HEIGHT]);

unsigned char mss_verify(struct mss_node authpath[MSS_HEIGHT], const unsigned char *v, const char *M, short len,
                         sponge_t *hash, sponge_t *pubk, dm_t *f, unsigned char *h, short leaf_index, const unsigned char *sig,
                         unsigned char *x, struct mss_node *currentLeaf, unsigned char merklePubKey[NODE_VALUE_SIZE]);

#endif // __MSS_H
