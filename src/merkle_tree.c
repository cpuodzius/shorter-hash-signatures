#include <stdio.h>
#include <stdlib.h>
#include "merkletree.h"

enum TREEHASH_STATE {
	TREEHASH_NEW		= 0x20,
	TREEHASH_RUNNING	= 0x40,
	TREEHASH_FINISHED	= 0x80
};

#define TREEHASH_MASK			0x1F
#define TREEHASH_HEIGHT_INFINITY	0x7F

#if defined(DEBUG)

#include "util.h"

void print_auth(struct state_mt *state) {
	short i;
	// Print Auth
	printf("\nAuthentication Path\n");
	for(i = 0; i < MERKLE_TREE_HEIGHT - 1; i++) {
		printf("Node[%d, %d]: ", state->auth[i].height, state->auth[i].pos);
		Display("", state->auth[i].value, NODE_VALUE_SIZE);
	}
}

void print_treehash(struct state_mt *state) {
	short i;
	// Print Treehash
	printf("\nTreehash\n");
	for(i = 0; i < MERKLE_TREE_TREEHASH_SIZE; i++) {
		printf("Node[%d, %d]: ", state->treehash[i].height, state->treehash[i].pos);
		Display("", state->treehash[i].value, NODE_VALUE_SIZE);
	}
}

void print_retain(struct state_mt *state) {
	short i;
	// Print Retain
	printf("\nRetain\n");
	for(i = MERKLE_TREE_HEIGHT - 2; i >= MERKLE_TREE_HEIGHT - MERKLE_TREE_K; i--) {
		short pos = (1 << (MERKLE_TREE_HEIGHT - i)) - 1;
		short index = (1 << (MERKLE_TREE_HEIGHT - i - 1)) - (MERKLE_TREE_HEIGHT - i - 1) - 1 + (pos >> 1) - 1;
		printf("\tNode[%d, %d]: ", state->retain[index].height, state->retain[index].pos);
		Display("", state->retain[index].value, NODE_VALUE_SIZE);
	}
}

#endif

void _create_leaf(sponge_t *hash, sponge_t *priv, sponge_t *pubk, struct node_t *node, short pos, unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)]) {
	node->height = 0;
	node->pos = pos;
	sinit(hash, MERKLE_TREE_SEC_LVL);
	absorb(hash, seed, NODE_VALUE_SIZE);
	absorb(hash, &pos, sizeof(pos));
	squeeze(hash, seed, LEN_BYTES(MERKLE_TREE_SEC_LVL)); // seed <- H(seed, pos)
	winternitzGen(seed, LEN_BYTES(WINTERNITZ_SEC_LVL), priv, hash, pubk, node->value);
}

void _stack_push(struct node_t stack[MERKLE_TREE_KEEP_SIZE], short *index, struct node_t *node) {
	stack[*index] = *node;
	*index = *index + 1;
}

void _stack_pop(struct node_t stack[MERKLE_TREE_KEEP_SIZE], short *index, struct node_t *node) {
	*node = stack[--*index];
}

void _get_parent(sponge_t *h, struct node_t *child1, struct node_t *child2, struct node_t *parent) {
	sinit(h, MERKLE_TREE_SEC_LVL);
	absorb(h, child1->value, NODE_VALUE_SIZE);
	absorb(h, child2->value, NODE_VALUE_SIZE);
	squeeze(h, parent->value, NODE_VALUE_SIZE);
	parent->height++;
	parent->pos >>= 1;
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
		state->treehash_state[i] = TREEHASH_NEW;
}

void _treehash_set_tailheight(struct state_mt *state, unsigned char h, unsigned char height) {
	state->treehash_state[h] |= (TREEHASH_MASK & height);
}

unsigned char _treehash_get_tailheight(struct state_mt *state, unsigned char h) {
	return (TREEHASH_MASK & state->treehash_state[h]);
}

void _treehash_state(struct state_mt *state, unsigned char h, enum TREEHASH_STATE th_state) {
	state->treehash_state[h] &= TREEHASH_MASK; // clean state
	state->treehash_state[h] |= th_state;
}

void _treehash_initialize(struct state_mt *state, unsigned char h, short s) {
	state->treehash_seed[h] = s;
}

unsigned char _treehash_height(struct state_mt *state, unsigned char h) {
	unsigned char height;
	switch(state->treehash_state[h] & ~TREEHASH_MASK) {
		case TREEHASH_NEW:
			height = h;
			break;
		case TREEHASH_RUNNING:
			if((state->treehash_state[h] & TREEHASH_MASK) == h)
				height = TREEHASH_HEIGHT_INFINITY;
			else
				height = (state->treehash_state[h] & TREEHASH_MASK);
			break;
		case TREEHASH_FINISHED:
			height = TREEHASH_HEIGHT_INFINITY;
			break;
	}
	return height;
}

void _treehash_update(sponge_t *hash, sponge_t *priv, sponge_t *pubk, struct state_mt *state, unsigned char h, struct node_t *node1, struct node_t *node2, unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)]) {
	_create_leaf(hash, priv, pubk, node1, state->treehash_seed[h], seed);
	_treehash_set_tailheight(state, h, 0);

	while(state->stack_index > 0 && _treehash_get_tailheight(state, h) == state->stack[state->stack_index - 1].height &&
											_treehash_get_tailheight(state, h) < h) {
		_stack_pop(state->stack, &state->stack_index, node2);
		_get_parent(hash, node1, node2, node1);
		_treehash_set_tailheight(state, h, _treehash_get_tailheight(state, h) + 1);
	}

	if(_treehash_get_tailheight(state, h) + 1 < h)
		_stack_push(state->stack, &state->stack_index, node1);
	else {
		if(!(state->treehash_state[h] & TREEHASH_FINISHED)) {
			*node2 = state->treehash[h];
			_get_parent(hash, node1, node2, node1);
			_treehash_set_tailheight(state, h, _treehash_get_tailheight(state, h) + 1);
		}
		state->treehash[h] = *node1;
	}
}

void _retain_push(struct state_mt *state, struct node_t *node) {
	short index = (1 << (MERKLE_TREE_HEIGHT - node->height - 1)) - (MERKLE_TREE_HEIGHT - node->height - 1) - 1 + (node->pos >> 1) - 1;
	state->retain[index] = *node;
}

void _retain_pop(struct state_mt *state, struct node_t *node) {
	*node = state->retain[state->retain_index++];
}

void mt_keygen(sponge_t *hash, sponge_t *priv, sponge_t *pubk, unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], struct node_t *node1, struct node_t *node2, struct state_mt *state, unsigned char pkey[NODE_VALUE_SIZE]) {
	short i, height = 0, pos = 0, index = 0;
	for(i = 0; i < N_NODES; i++) {
		if(height == 0) {
			_create_leaf(hash, priv, pubk, node1, pos, seed);
		}
		else {
			_stack_pop(state->keep, &index, node2);
			_get_parent(hash, node1, node2, node1);
			_stack_push(state->keep, &index, node1);
		}
		if(pos == 1 && height < MERKLE_TREE_HEIGHT - 1)
			state->auth[height] = *node1;
		else if(pos == 3 && height < MERKLE_TREE_HEIGHT - MERKLE_TREE_K)
			state->treehash[height] = *node1;
		else if(pos > 3 && (pos & 1) == 1 && height >= MERKLE_TREE_HEIGHT - MERKLE_TREE_K)
			_retain_push(state, node1);
		_next_node(&height, &pos);
#if defined(DEBUG)
		printf("h=%d, pos=%d\n", height, pos);
		Display("Node: ", node1->value, NODE_VALUE_SIZE);
#endif
	}
#if defined(DEBUG)
	print_auth(state);
	print_treehash(state);
	print_retain(state);
#endif
	for(i = 0; i < NODE_VALUE_SIZE; i++)
		pkey[i] = node1->value[i];
}

void _nextAuth(struct state_mt *state, unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], sponge_t *hash, sponge_t *priv, sponge_t *pubk, struct node_t *node1, struct node_t *node2, short s) {
	short tau = MERKLE_TREE_HEIGHT - 1, h, min;

	while((1 << tau) % (s + 1) != 0) {
		tau--;
	}

	if(tau < MERKLE_TREE_HEIGHT - 1 && (((s >> (tau + 1)) & 1) == 0))
		state->keep[tau] = state->auth[tau];

	if(tau == 0)
		_create_leaf(hash, priv, pubk, &state->auth[0], s, seed);
	else {
		_get_parent(hash, &state->auth[tau - 1], &state->keep[tau - 1], &state->auth[tau]);
		min = (tau - 1 < MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 1) ? tau - 1 : MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 1;
		for(h = 0; h <= min; h++) {
			state->auth[h] = state->treehash[h];
			if(s + 1 + 3 * (1 << h) < (1 << MERKLE_TREE_HEIGHT))
				_treehash_initialize(state, h, s + 1 + 3 * (1 << h));
			else
				_treehash_state(state, h, TREEHASH_FINISHED);
		}
		h = MERKLE_TREE_HEIGHT - MERKLE_TREE_K;
		while(h < tau) {
			_retain_pop(state, &state->auth[h]);
			h++;
		}
	}
	// UPDATE
	short i, j, k;
	min = TREEHASH_HEIGHT_INFINITY;
	for(i = 0; i < (MERKLE_TREE_HEIGHT - MERKLE_TREE_K) / 2; i++) {
		for(j = MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 1; j >= 0; j--) {
			if(_treehash_height(state, j) <= min) {
				min = state->treehash[j].height;
				k = j;
			}
		}
		_treehash_update(hash, priv, pubk, state, k, node1, node2, seed);
	}
}


void merkletreeSig(const byte s[/*m*/], const byte v[/*m*/], const uint m, const byte *M, uint len, sponge_t *priv, sponge_t *hash, byte h[/*m*/], unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], short pos) {
}

#if defined(DEBUG)

// Return the index of the authentication path for s-th leaf
void get_auth_index(short s, short auth_index[MERKLE_TREE_HEIGHT - 1]) {
	short h;
	for(h = 0; h < MERKLE_TREE_HEIGHT; h++) {
		if(s % 2 == 0)
			auth_index[h] = s + 1;
		else
			auth_index[h] = s - 1;
		s >>= 1;
	}	
}

void print_auth_index(short auth_index[MERKLE_TREE_HEIGHT - 1]) {
	printf("Expected index:\n");
	short h;
	for(h = MERKLE_TREE_HEIGHT - 1; h >= 0; h--)
		printf("\th = %d : n[%d][%d]\n", h, h, auth_index[h]);
}
#endif


#if defined(MERKLE_TREE_SELFTEST) || defined(DEBUG)

#include <time.h>
#include "util.h"

int main() {
	printf("\n Parameters:  sec lvlH=%u, H=%u, #nodes=%u, node size=%u, winternitz_w=%u \n\n", MERKLE_TREE_SEC_LVL, MERKLE_TREE_HEIGHT, N_NODES, NODE_VALUE_SIZE, WINTERNITZ_W);

	// Execution variables
	unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)];
	unsigned char pkey[NODE_VALUE_SIZE];
	sponge_t sponges[3];
	struct node_t nodes[2];
	struct state_mt state;

	// Test variables
	clock_t elapsed;
	unsigned char j;
	short auth_index[MERKLE_TREE_HEIGHT - 1];

	// Count only execution variables
	printf("RAM total: %luB\n", (long unsigned int)(sizeof(seed) + sizeof(pkey) + sizeof(sponges) + sizeof(nodes) + sizeof(state)));

	for (j = 0; j < LEN_BYTES(MERKLE_TREE_SEC_LVL); j++) {
		seed[j] = 0xA0 ^ j; // sample private key, for debugging only
	}
	Display("\n seed for keygen: ",seed,LEN_BYTES(MERKLE_TREE_SEC_LVL));

	//struct timeval t_start, t_end;
        short i, ntest = 10;
	elapsed = -clock();
	//gettimeofday(&t_start, NULL);
	for(i = 0; i < ntest; i++) {
		init_state(&state);
		mt_keygen(&sponges[0] , &sponges[1], &sponges[2], seed, &nodes[0], &nodes[1], &state, pkey);
#if defined(DEBUG)
		Display(" Merkle Tree (pkey)\n", pkey, NODE_VALUE_SIZE);
		for(j = 0; j < (1 << MERKLE_TREE_HEIGHT); j++) {
			printf("s = %d  ", j);
			_nextAuth(&state, seed, &sponges[0], &sponges[1], &sponges[2], &nodes[0], &nodes[1], j);
			print_auth(&state);
			get_auth_index(j, auth_index);
			print_auth_index(auth_index);
		}
#endif
	}
	//gettimeofday(&t_end, NULL);
	elapsed += clock();
	//printf("Tempo de execucao %ld.%ldms\n", (t_end.tv_usec - t_start.tv_usec) / ntest / 1000, ((t_end.tv_usec - t_start.tv_usec) / ntest) % 1000);
	printf("KeyGen Elapsed time: %.1f ms\n", 1000*(float)elapsed/CLOCKS_PER_SEC/ntest);

	return 0;
}
#endif
