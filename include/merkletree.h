#ifndef __MERKLETREE_H
#define __MERKLETREE_H

#include "winternitz.h"

// Merkle Tree interface:
#ifdef __cplusplus
extern "C" {
#endif

#if defined(MERKLE_TREE_SELFTEST) || defined(DEBUG)
#define MERKLE_TREE_SEC_LVL                     WINTERNITZ_SEC_LVL
#define MERKLE_TREE_HEIGHT                      5
#define MERKLE_TREE_K		                1
#else
#define MERKLE_TREE_SEC_LVL                     WINTERNITZ_SEC_LVL
#define MERKLE_TREE_HEIGHT                      14		// Heightst tree for this implementation (because type of index is short)
#define MERKLE_TREE_K	                      	2
#endif

#define MERKLE_TREE_TREEHASH_SIZE		MERKLE_TREE_HEIGHT - MERKLE_TREE_K
#define MERKLE_TREE_STACK_SIZE			MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 2
#define MERKLE_TREE_KEEP_SIZE			MERKLE_TREE_HEIGHT + 1 // Keep is used as stack during key generation
#define MERKLE_TREE_RETAIN_SIZE			(1 << MERKLE_TREE_K) - MERKLE_TREE_K - 1

#define N_NODES ((1 << (MERKLE_TREE_HEIGHT + 1)) - 1)
#define NODE_VALUE_SIZE LEN_BYTES(MERKLE_TREE_SEC_LVL)          // each value element is a byte

struct node_t {
        short height, pos;
        unsigned char value[NODE_VALUE_SIZE];           // node's value for auth path   
};

struct state_mt {
	short stack_index, retain_index, treehash_index[MERKLE_TREE_TREEHASH_SIZE];
        struct node_t treehash[MERKLE_TREE_TREEHASH_SIZE];
        struct node_t stack[MERKLE_TREE_STACK_SIZE];
        struct node_t retain[MERKLE_TREE_RETAIN_SIZE];
        struct node_t keep[MERKLE_TREE_KEEP_SIZE];
        struct node_t auth[MERKLE_TREE_HEIGHT - 1];
};

void init_state(struct state_mt* state);

void mt_keygen(unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], struct node_t *node, struct state_mt *state, unsigned char pkey[NODE_VALUE_SIZE]);

#ifdef __cplusplus
};
#endif


#endif // __MERKLETREE_H
