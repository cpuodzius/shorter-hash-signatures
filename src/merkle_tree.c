#include <stdio.h>
#include <stdlib.h>
#include "merkletree.h"

#define TREEHASH_INITIALIZATION	0xFF

#if defined(DEBUG)
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
#endif

void _create_leaf(struct node_t *node, short pos, unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)]) {
	node->height = 0;
	node->pos = pos;
	sponge_t h;
	sinit(&h, MERKLE_TREE_SEC_LVL);
	absorb(&h, seed, NODE_VALUE_SIZE);
	absorb(&h, &pos, sizeof(pos));
	squeeze(&h, node->value, NODE_VALUE_SIZE);
	/*
	*	Generate here W-OTS keys
	*/
}

void _keygen_stack_push(struct node_t stack[MERKLE_TREE_KEEP_SIZE], short *index, struct node_t *node) {
	stack[*index] = *node;
	*index = *index + 1;
}

void _keygen_stack_pop(struct node_t stack[MERKLE_TREE_KEEP_SIZE], short *index, struct node_t *node) {
	*node = stack[--*index];
}

void _get_inner_node(struct node_t *node, short height, short pos, struct node_t stack[MERKLE_TREE_KEEP_SIZE], short *index) {
	sponge_t h;
	sinit(&h, MERKLE_TREE_SEC_LVL);
	_keygen_stack_pop(stack, index, node);
	absorb(&h, node->value, NODE_VALUE_SIZE);
	_keygen_stack_pop(stack, index, node);
	absorb(&h, node->value, NODE_VALUE_SIZE);
	squeeze(&h, node->value, NODE_VALUE_SIZE);
	node->height = height;
	node->pos = pos;
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

void init_state(struct state_mt *state) {
	short i;
	state->stack_index = 0;
	state->retain_index = 0;
	for(i = 0; i < MERKLE_TREE_TREEHASH_SIZE; i++)
		state->treehash_index[i] = TREEHASH_INITIALIZATION;
}

void _stack_push(struct state_mt *state, struct node_t *node) {
	state->stack[state->stack_index] = *node;
	state->stack_index = state->stack_index + 1;
	printf("Stack height = %d\n", state->stack_index);
}

void _stack_pop(struct state_mt *state, struct node_t *node) {
	*node =	state->stack[--state->stack_index];
	printf("Stack height = %d\n", state->stack_index);
}

void _treehash_terminate(struct state_mt *state, short height) {
	state->treehash_index[height] = TREEHASH_INITIALIZATION;
}

void _treehash_push(struct state_mt *state, short height, struct node_t *node) {
	if(state->treehash_index[height] == TREEHASH_INITIALIZATION) {
		state->treehash[height] = *node;
		state->treehash_index[height] = 1;
	}
	else if(state->treehash_index[height] == 0) {
		state->treehash[state->treehash_index[height]] = *node;
		state->treehash_index[height] = state->treehash_index[height] + 1;
	}
	else {
		_stack_push(state, node);
		state->treehash_index[height] = state->stack_index + 1;
	} 
}

void _treehash_pop(struct state_mt *state, short height, struct node_t *node) {
	if(state->treehash_index[height] == 1) {
		*node =	state->treehash[height];
		state->treehash_index[height] = 0;
	}
	else {
		_stack_pop(state, node);
		state->treehash_index[height]--;
	}
}

void _retain_push(struct state_mt *state, struct node_t *node) {
	short index = (1 << (MERKLE_TREE_HEIGHT - node->height - 1)) - (MERKLE_TREE_HEIGHT - node->height - 1) - 1 + (node->pos >> 1) - 1;
	state->retain[index] = *node;
}

void _retain_pop(struct state_mt *state, struct node_t *node) {
	*node = state->retain[state->retain_index++];
}

void mt_keygen(unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], struct node_t *node, struct state_mt *state, unsigned char pkey[NODE_VALUE_SIZE]) {
	short i, height, pos, index = 0;
	for(i = 0; i < N_NODES; i++) {
		if(i == 0) {
			height = 0;
			pos = 0;
		}
		else
			_next_node(&height, &pos);
		if(height == 0) {
			_create_leaf(node, pos, seed);
			_keygen_stack_push(state->keep, &index, node);
		}
		else {
			_get_inner_node(node, height, pos, state->keep, &index);
			_keygen_stack_push(state->keep, &index, node);
		}
		if(pos == 1)
			state->auth[height] = *node;
		else if(pos == 3 && height < MERKLE_TREE_HEIGHT - MERKLE_TREE_K)
			_treehash_push(state, height, node);
		else if(pos > 3 && (pos & 1) == 1 && height >= MERKLE_TREE_HEIGHT - MERKLE_TREE_K)
			_retain_push(state, node);
#if defined(DEBUG)
		printf("h=%d, pos=%d\n", height, pos);
		Display("Node: ", node->value, NODE_VALUE_SIZE);
#endif
	}
	state->stack_index = 0;
#if defined(DEBUG)
		short j;
		// Print Auth
		printf("\nAuthentication Path\n");
		for(j = 0; j < MERKLE_TREE_HEIGHT; j++) {
			printf("Node[%d, %d]: ", state->auth[j].height, state->auth[j].pos);
			Display("", state->auth[j].value, NODE_VALUE_SIZE);
		}
		// Print Treehash
		printf("\nTreehash\n");
		for(j = 0; j < MERKLE_TREE_TREEHASH_SIZE; j++) {
			int k;
			printf("\nTreehash_%d\n", j);
			if(state->treehash_index[j] != TREEHASH_INITIALIZATION) {
				for(k = state->treehash_index[j] - 1; k >= 0; k--) {
					if(k == 0) {
						printf("\tNode[%d, %d]: ", state->treehash[j].height, state->treehash[j].pos);
						Display("", state->treehash[j].value, NODE_VALUE_SIZE);
					}
					else {
						printf("\tNode[%d, %d]: ", state->stack[k].height, state->stack[k].pos);
						Display("", state->stack[k].value, NODE_VALUE_SIZE);
					}
				}
			}
		}
		// Print Retain
		printf("\nRetain\n");
		for(j = MERKLE_TREE_HEIGHT - 2; j >= MERKLE_TREE_HEIGHT - MERKLE_TREE_K; j--) {
			short pos = (1 << (MERKLE_TREE_HEIGHT - j)) - 1;
			short index = (1 << (MERKLE_TREE_HEIGHT - j - 1)) - (MERKLE_TREE_HEIGHT - j - 1) - 1 + (pos >> 1) - 1;
			printf("\tNode[%d, %d]: ", state->retain[index].height, state->retain[index].pos);
			Display("", state->retain[index].value, NODE_VALUE_SIZE);
		}
#endif
	for(i = 0; i < NODE_VALUE_SIZE; i++)
		pkey[i] = node->value[i];
}



#if defined(MERKLE_TREE_SELFTEST) || defined(DEBUG)
unsigned char rand_dig_f(void) {
    return (unsigned char)rand();
}

#include <sys/time.h>

int main() {
	unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)];

	printf("\n Parameters:  sec lvlH=%u, H=%u, #nodes=%u, node size=%u \n\n", MERKLE_TREE_SEC_LVL, MERKLE_TREE_HEIGHT, N_NODES, NODE_VALUE_SIZE);	

	unsigned char pkey[NODE_VALUE_SIZE];
	struct state_mt state;
	struct node_t node;

	printf("RAM total: %luB\n", sizeof(pkey) + sizeof(state) + sizeof(node));
	
	// Note that this function is not a secure pseudo-random function. It was only used for tests.
	//srand((unsigned int)time((time_t *)NULL));
    	srand(0);
    	short seedd = Rand(seed, MERKLE_TREE_SEC_LVL, rand_dig_f);
    	Display("\n seed for keygen: ",seed,seedd);



	struct timeval t_start, t_end;
        short i, ntest = 20;

	gettimeofday(&t_start, NULL);
	for(i = 0; i < ntest; i++) {
		init_state(&state);
		mt_keygen(seed, &node, &state, pkey);
#if defined(DEBUG)
		Display(" Merkle Tree (pkey)\n", pkey, NODE_VALUE_SIZE);
#endif
	}
	gettimeofday(&t_end, NULL);

	printf("Tempo de execucao %ld.%ldms\n", (t_end.tv_usec - t_start.tv_usec) / ntest / 1000, ((t_end.tv_usec - t_start.tv_usec) / ntest) % 1000);

	return 0;
}
#endif
