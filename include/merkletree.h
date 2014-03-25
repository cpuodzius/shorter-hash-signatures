#ifndef __MERKLETREE_H
#define __MERKLETREE_H

#include "winternitz.h"

// Merkle Tree interface:
#ifdef __cplusplus
extern "C" {
#endif

#define odd(x)	((x) % 2)

#if defined(MERKLE_TREE_SELFTEST) || defined(DEBUG)
#define MERKLE_TREE_SEC_LVL                     WINTERNITZ_SEC_LVL
#define MERKLE_TREE_HEIGHT			6//5//6//6//4
#define MERKLE_TREE_K				2//3//4//2//2
#else
#define MERKLE_TREE_SEC_LVL                     WINTERNITZ_SEC_LVL
#define MERKLE_TREE_HEIGHT                      14		// Heightst tree for this implementation (because type of index is short)
#define MERKLE_TREE_K	                      	2
#endif

#if odd(MERKLE_TREE_HEIGHT - MERKLE_TREE_K)
#error (H - K) must be even
#endif

#define MERKLE_TREE_TREEHASH_SIZE		MERKLE_TREE_HEIGHT - MERKLE_TREE_K
#define MERKLE_TREE_STACK_SIZE			MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 2
#define MERKLE_TREE_KEEP_SIZE			MERKLE_TREE_HEIGHT // Keep is used as stack during key generation
#define MERKLE_TREE_RETAIN_SIZE			(1 << MERKLE_TREE_K) - MERKLE_TREE_K - 1

#define NODE_VALUE_SIZE LEN_BYTES(MERKLE_TREE_SEC_LVL)          // each value element is a byte

struct node_t {
        short height, pos;
        unsigned char value[NODE_VALUE_SIZE];           // node's value for auth path
};

//treehash_seed: index of the seed for the treehash of height h
struct state_mt {
	unsigned char treehash_state[MERKLE_TREE_TREEHASH_SIZE];
	short stack_index, retain_index[MERKLE_TREE_K-1], treehash_seed[MERKLE_TREE_TREEHASH_SIZE];
        struct node_t treehash[MERKLE_TREE_TREEHASH_SIZE];
        struct node_t stack[MERKLE_TREE_STACK_SIZE];
        struct node_t retain[MERKLE_TREE_RETAIN_SIZE];
        struct node_t keep[MERKLE_TREE_KEEP_SIZE];
        struct node_t auth[MERKLE_TREE_HEIGHT];
};

void init_state(struct state_mt* state);

void mt_keygen(sponge_t *hash, sponge_t *priv, sponge_t *pubk, unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], struct node_t *node1, struct node_t *node2, struct state_mt *state, unsigned char pkey[NODE_VALUE_SIZE]);

#ifdef __cplusplus
};
#endif


#endif // __MERKLETREE_H
