#include <stdio.h>
#include <stdlib.h>
#include "merkletree.h"

void _print_node(struct node_t node) {
	printf("[");
	//short i;
	/*for(i = 0; i < NODE_VALUE_SIZE; i++) {
		printf("%X", (node.value[i] >> 4) & 0x0F);
		printf("%X", node.value[i] & 0x0F);
	}*/
	printf("%u,%u", node.height, node.pos);
	printf("]");
}

void _create_leaf(struct node_t *node, short height, short pos, unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)]) {
	node->height = height;
	node->pos = pos;
	sponge_t h;
	sinit(&h, MERKLE_TREE_SEC_LVL);
	absorb(&h, seed, NODE_VALUE_SIZE);
	squeeze(&h, seed, NODE_VALUE_SIZE);
	/*
	*	Generate here W-OTS keys
	*/
	/****** JUST FOR TESTS ********/
	int i;
	for(i = 0; i < NODE_VALUE_SIZE; i++)
		node->value[i] = seed[i];
	/******************************/
	squeeze(&h, seed, NODE_VALUE_SIZE);
}

void _get_inner_node(struct node_t *node, short height, short pos, struct stack_mt* stack) {
	node->height = height;
	node->pos = pos;
	sponge_t h;
	sinit(&h, MERKLE_TREE_SEC_LVL);
	*node = stack_pop(stack);
	absorb(&h, node->value, NODE_VALUE_SIZE);
	*node = stack_pop(stack);
	absorb(&h, node->value, NODE_VALUE_SIZE);
	squeeze(&h, node->value, NODE_VALUE_SIZE);
}

/**
 * @param index		The index of node in array
 * @param height, pos	The height and position of input node in the tree
 */
void _next_node(short *height, short *pos) {
	if((*pos & 1) == 1) {	// pos is odd
		*height = *height + 1;
		*pos /= 2;
	}
	else {
		if(*height == 0)
			*pos = *pos + 1;
		else {
			*pos = ((*pos >> 1) * (1 << (*height + 1))) + (1 << *height);
			*height = 0;
		}
	}
}

void stack_init(struct stack_mt* stack) {
	stack->index = -1;
}

void stack_push(struct stack_mt* stack, struct node_t node) {
	stack->nodes[++stack->index] = node;
}

struct node_t stack_pop(struct stack_mt* stack) {
	stack->index--;
	return stack->nodes[stack->index + 1];
}

void mt_keygen(unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], struct node_t keep[2 * MERKLE_TREE_HEIGHT - 1], unsigned char pkey[NODE_VALUE_SIZE]) {
	short i, height, pos;
	struct node_t node;
	struct stack_mt	stack;
	stack_init(&stack);
	for(i = 0; i < N_NODES; i++) {
		if(i == 0) {
			height = 0;
			pos = 0;
		}
		else
			_next_node(&height, &pos);
		if(height == 0) {
			_create_leaf(&node, height, pos, seed);
			stack_push(&stack, node);
		}
		else {
			_get_inner_node(&node, height, pos, &stack);
			stack_push(&stack, node);
		}
		if(pos == 1 || pos == 3) {
			short index = (2 * MERKLE_TREE_HEIGHT - 1) - 1 - ((2 * height) + (pos / 2));
			keep[index] = node;
		}
#if defined(MERKLE_TREE_SELFTEST)
		//printf("h=%d, pos=%d\n", height, pos);
		//Display("Node: ", node.value, NODE_VALUE_SIZE);
#endif
	}
	for(i = 0; i < NODE_VALUE_SIZE; i++)
		pkey[i] = node.value[i];
}

#if defined(MERKLE_TREE_SELFTEST)
unsigned char rand_dig_f(void) {
    return (unsigned char)rand();
}

#include <sys/time.h>

int main() {
	unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)];

	printf("\n Parameters:  sec lvlH=%u, H=%u, #nodes=%u, node size=%u \n\n", MERKLE_TREE_SEC_LVL, MERKLE_TREE_HEIGHT, N_NODES, NODE_VALUE_SIZE);	

	// Note that this function is not a secure pseudo-random function. It was only used for tests.
	//srand((unsigned int)time((time_t *)NULL));
    	srand(0);
    	short seedd = Rand(seed, MERKLE_TREE_SEC_LVL, rand_dig_f);
    	Display("\n seed for keygen: ",seed,seedd);

	unsigned char pkey[NODE_VALUE_SIZE];
	struct node_t keep[2 * MERKLE_TREE_HEIGHT - 1];

	struct timeval t_start, t_end;

	gettimeofday(&t_start, NULL);

	mt_keygen(seed, keep, pkey);

	gettimeofday(&t_end, NULL);

	Display("Merkle Tree (pkey)\n", pkey, NODE_VALUE_SIZE);
	printf("Tempo de execucao %lums\n", t_end.tv_usec - t_start.tv_usec);

	return 0;
}
#endif
