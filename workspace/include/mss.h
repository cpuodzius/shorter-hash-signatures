#ifndef __MSS_H
#define __MSS_H

#include "winternitz.h"

#ifdef MSS_ROM_RETAIN
	#include "retain.h"
#endif

// Improved Merkle Signature Scheme targeting 16-bit platforms
// 16 is the Heighest tree for this implementation (since leaf index is of type short)

#define MSS_OK 1
#define MSS_ERROR 0

#define MSS_SEC_LVL                     WINTERNITZ_SEC_LVL
#define MSS_HEIGHT			11
#define MSS_K				9

#define odd(x)	((x) % 2)
#if odd(MSS_HEIGHT - MSS_K)
#error (H - K) must be even
#endif

#define MSS_TREEHASH_SIZE		MSS_HEIGHT - MSS_K
#define MSS_STACK_SIZE			MSS_HEIGHT - MSS_K - 2
#define MSS_KEEP_SIZE			MSS_HEIGHT // Keep is used as stack during key generation
#ifdef MSS_ROM_RETAIN
	#define MSS_RETAIN_SIZE			0 // retain already precomputed, load from ROM
#else
	#define MSS_RETAIN_SIZE			(1 << MSS_K) - MSS_K - 1
#endif

#define NODE_VALUE_SIZE LEN_BYTES(MSS_SEC_LVL)         // each value element is a byte

struct mss_node {
        unsigned char height;
        unsigned short index;
        unsigned char value[NODE_VALUE_SIZE];           // node's value for auth path
};

//treehash_seed: index of the seed for the treehash of height h
struct state_mt {
	unsigned char treehash_state[MSS_TREEHASH_SIZE];
	unsigned short stack_index, retain_index[MSS_K-1], treehash_seed[MSS_TREEHASH_SIZE];
        struct mss_node treehash[MSS_TREEHASH_SIZE];
        struct mss_node stack[MSS_STACK_SIZE];
        struct mss_node retain[MSS_RETAIN_SIZE];
        struct mss_node keep[MSS_KEEP_SIZE];
        struct mss_node auth[MSS_HEIGHT];
	struct mss_node store[MSS_TREEHASH_SIZE-1];
};

#ifndef PLATFORM_SENSOR

#define MSS_NODE_SIZE	3 + LEN_BYTES(MSS_SEC_LVL)
#define MSS_STATE_SIZE	(MSS_TREEHASH_SIZE + 2 * (MSS_K + MSS_TREEHASH_SIZE) + MSS_NODE_SENSOR * (MSS_TREEHASH_SIZE + MSS_STACK_SIZE + MSS_RETAIN_SIZE + MSS_RETAIN_SIZE + MSS_KEEP_SIZE + MSS_HEIGHT + MSS_TREEHASH_SIZE - 1))
#define MSS_KEY_SIZE	(MSS_STATE_SIZE + LEN_BYTES(MSS_SEC_LVL))

unsigned char *mss_keygen(unsigned char seed[LEN_BYTES(MSS_SEC_LVL)]);
unsigned char *mss_sign(unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], unsigned char skey[MSS_KEY_SIZE], char *msg);
unsigned char *mss_verify(unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], unsigned char pkey[MSS_KEY_SIZE], char *msg);

#else

void mss_keygen_core(dm_t *hash, mmo_t *mmo, unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], struct mss_node *node1, struct mss_node *node2, struct state_mt *state, unsigned char pkey[NODE_VALUE_SIZE]);
void mss_sign_core(struct state_mt *state, unsigned char *seed, struct mss_node *leaf, const char *msg, unsigned short len, mmo_t *mmo, dm_t *f, unsigned char *h, unsigned short leaf_index, struct mss_node *node1, struct mss_node *node2, unsigned char *ots, struct mss_node authpath[MSS_HEIGHT]);
unsigned char mss_verify_core(struct mss_node authpath[MSS_HEIGHT], const unsigned char *v, const char *msg, unsigned short len, mmo_t *mmo, dm_t *f, unsigned char *h, unsigned short leaf_index, const unsigned char *ots, unsigned char *x, struct mss_node *current_leaf, unsigned char pkey[NODE_VALUE_SIZE]);

#endif



#endif // __MSS_H
