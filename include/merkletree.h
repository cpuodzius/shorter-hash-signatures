#ifndef __MERKLETREE_H
#define __MERKLETREE_H

#include "winternitz.h"

// Merkle Tree interface:
#ifdef __cplusplus
extern "C" {
#endif

#if defined(MERKLE_TREE_SELFTEST)
#define MERKLE_TREE_SEC_LVL                     WINTERNITZ_SEC_LVL
#define MERKLE_TREE_HEIGHT                      5
#else
#define MERKLE_TREE_SEC_LVL                     WINTERNITZ_SEC_LVL
#define MERKLE_TREE_HEIGHT                      16
#endif

#define N_NODES ((1 << (MERKLE_TREE_HEIGHT + 1)) - 1)
#define NODE_VALUE_SIZE LEN_BYTES(MERKLE_TREE_SEC_LVL)          // each value element is a byte

struct node_t {
        short height, pos;
        unsigned char value[NODE_VALUE_SIZE];           // node's value for auth path   
};

struct stack_mt {
        short index;
        struct node_t nodes[MERKLE_TREE_HEIGHT];
};

void stack_init(struct stack_mt* stack);
void stack_push(struct stack_mt* stack, struct node_t node);
struct node_t stack_pop(struct stack_mt* stack);

void mt_keygen(unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], struct node_t keep[2 * MERKLE_TREE_HEIGHT - 1], unsigned char pkey[NODE_VALUE_SIZE]);

#ifdef __cplusplus
};
#endif


#endif // __MERKLETREE_H
