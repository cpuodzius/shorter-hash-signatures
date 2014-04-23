#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "merkletree.h"

enum TREEHASH_STATE {
	TREEHASH_NEW		= 0x20,
	TREEHASH_RUNNING	= 0x40,
	TREEHASH_FINISHED	= 0x80
};

#define TREEHASH_MASK			0x1F
#define TREEHASH_HEIGHT_INFINITY	0x7F

#if defined(DEBUG)

#include <assert.h>
#include "util.h"

char dbg_seed_initialized = 0;
unsigned char dbg_seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)];

short _node_valid_index(short height, short pos) {
	short valid_height = 0;
	short valid_pos = 0;
	if(height >= 0 && height <= MERKLE_TREE_HEIGHT) {
		valid_height = 1;
		if((pos >= 0) && (pos < (1 << (MERKLE_TREE_HEIGHT - height))))
			valid_pos = 1;
	}
	return (valid_height && valid_pos);
}

short _node_valid(const struct node_t *node) {
	short valid_value_size = 0;
	if(sizeof(node->value) == LEN_BYTES(MERKLE_TREE_SEC_LVL))
		valid_value_size = 1;
	return (valid_value_size && _node_valid_index(node->height, node->pos));
}

short _node_equal(const struct node_t *node1, const struct node_t *node2) {
	char equal = 0;
	if(node1->height == node2->height && node1->pos == node2->pos)
		equal = (memcmp(node1->value, node2->value, NODE_VALUE_SIZE) == 0);
	return equal;
}

short _is_left_node(const struct node_t *node) {
	return ((node->pos & 1) == 0);
}

short _is_right_node(const struct node_t *node) {
	return ((node->pos & 1) == 1);
}

short _node_brothers(const struct node_t *left_node, const struct node_t *right_node) {
	char brothers = 0;
	if(_node_valid(left_node) && _node_valid(right_node)) {
		if(left_node->height == right_node->height) {
			if((_is_left_node(left_node) && _is_right_node(right_node)) && (right_node->pos - left_node->pos == 1))
				brothers = 1;
		}
	}
	return brothers;
}

void print_auth(const struct state_mt *state) {
	short i;
	// Print Auth
	printf("\nAuthentication Path\n");
	for(i = 0; i < MERKLE_TREE_HEIGHT; i++) {
		printf("Node[%d, %d]", state->auth[i].height, state->auth[i].pos);
		Display("", state->auth[i].value, NODE_VALUE_SIZE);
	}
}

void print_treehash(const struct state_mt *state) {
	short i;
	// Print Treehash
	printf("\nTreehash\n");
	for(i = 0; i < MERKLE_TREE_TREEHASH_SIZE; i++) {
		printf("Node[%d, %d]", state->treehash[i].height, state->treehash[i].pos);
		Display("", state->treehash[i].value, NODE_VALUE_SIZE);
	}
}

void print_retain(const struct state_mt *state) {
	short h, j;
	// Print Retain
	printf("\nRetain\n");
	for(h = MERKLE_TREE_HEIGHT - 2; h >= MERKLE_TREE_HEIGHT - MERKLE_TREE_K; h--) {
		for (j = (1 << (MERKLE_TREE_HEIGHT - h - 1)) - 2; j >= 0; j--) {
			short pos = 2*j + 3;
			short index = (1 << (MERKLE_TREE_HEIGHT - h - 1)) - (MERKLE_TREE_HEIGHT - h - 1) - 1 + (pos >> 1) - 1;
			printf("\tNode[%d, %d]", state->retain[index].height, state->retain[index].pos);
			Display("", state->retain[index].value, NODE_VALUE_SIZE);
		}
	}
}

#endif

void _create_leaf(sponge_t *hash, sponge_t *priv, sponge_t *pubk, struct node_t *node, const short pos, const unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)]) {
	unsigned char seedPos[LEN_BYTES(MERKLE_TREE_SEC_LVL)];
#if defined(DEBUG)
	// seed must always be the same
	if(!dbg_seed_initialized) {
		dbg_seed_initialized = 1;
		memmove(dbg_seed, seed, LEN_BYTES(MERKLE_TREE_SEC_LVL));
	}
	else
		assert(memcmp(dbg_seed, seed, LEN_BYTES(MERKLE_TREE_SEC_LVL)) == 0);
	// pos must be a valid leaf index
	assert(_node_valid_index(0, pos));
#endif
	node->height = 0;
	node->pos = pos;
	sinit(hash, MERKLE_TREE_SEC_LVL);
	absorb(hash, seed, NODE_VALUE_SIZE);
	absorb(hash, &pos, sizeof(pos));
	squeeze(hash, seedPos, LEN_BYTES(MERKLE_TREE_SEC_LVL)); // seedPos <- H(seed, pos)
	winternitzGen(seedPos, LEN_BYTES(WINTERNITZ_SEC_LVL), priv, hash, pubk, node->value);
#if defined(DEBUG)
	assert(_node_valid(node));
	assert(node->height == 0);
	assert(node->pos == pos);
#endif
}

void _stack_push(struct node_t stack[MERKLE_TREE_KEEP_SIZE], short *index, struct node_t *node) {
#if defined(DEBUG)
	assert(*index >= 0);
	assert(_node_valid(node));
	const short prior_index = *index;
	short i;
	printf("----- _stack_push -----\n\n");
	printf("Stack before push:");
	if(*index == 0)
		printf(" empty\n");
	else
		printf("\n");
	for(i = *index - 1; i >= 0; i--) {
		printf("\nStack node: %d\n", i);
		printf("h=%d, pos=%d\n", stack[i].height, stack[i].pos);
		Display("Node", stack[i].value, NODE_VALUE_SIZE);
	}
	printf("\nNode to push\n");
	printf("h=%d, pos=%d\n", node->height, node->pos);
	Display("Node", node->value, NODE_VALUE_SIZE);
	//getchar();
#endif
	stack[*index] = *node;
	*index = *index + 1;
#if defined(DEBUG)
	printf("\nStack after push:");
	if(*index == 0)
		printf(" empty\n");
	else
		printf("\n");
	for(i = *index - 1; i >= 0; i--) {
		printf("\nStack node: %d\n", i);
		printf("h=%d, pos=%d\n", stack[i].height, stack[i].pos);
		Display("Node", stack[i].value, NODE_VALUE_SIZE);
	}
	assert(*index == prior_index + 1);
	printf("-----------------------\n");
	//getchar();
#endif
}

void _stack_pop(struct node_t stack[MERKLE_TREE_KEEP_SIZE], short *index, struct node_t *node) {
#if defined(DEBUG)
	assert(*index > 0);
	const short prior_index = *index;
#endif
	*node = stack[--*index];
#if defined(DEBUG)
	assert(_node_valid(node));
	assert(*index == prior_index - 1);
#endif
}

void _get_parent(sponge_t *h, const struct node_t *left_child, const struct node_t *right_child, struct node_t *parent) {
#if defined(DEBUG)
	assert(_node_valid(left_child));
	assert(_node_valid(right_child));
	// left_child and right_child must have the same height and be below the root
	assert(left_child->height < MERKLE_TREE_HEIGHT);
	assert(right_child->height < MERKLE_TREE_HEIGHT);
	assert(left_child->height == right_child->height);
	// left_child and right_child must be brothers
	// left_child->pos must be even and right_child->pos must be odd
	assert(_is_left_node(left_child));
	assert(_is_right_node(right_child));
	assert(right_child->pos == left_child->pos + 1);
	const short parent_height = right_child->height + 1;
	const short parent_pos = (right_child->pos / 2);
	/*
	printf("----- _get_parent -----\n\n");
	printf("Left Child\n");
	printf("h=%d, pos=%d\n", left_child->height, left_child->pos);
	Display("Node", left_child->value, NODE_VALUE_SIZE);
	printf("Right Child\n");
	printf("h=%d, pos=%d\n", right_child->height, right_child->pos);
	Display("Node", right_child->value, NODE_VALUE_SIZE);
	getchar();
	//*/
#endif
	sinit(h, MERKLE_TREE_SEC_LVL);
	absorb(h, left_child->value, NODE_VALUE_SIZE);
	absorb(h, right_child->value, NODE_VALUE_SIZE);
	squeeze(h, parent->value, NODE_VALUE_SIZE);
	parent->height = left_child->height + 1;
	parent->pos = (left_child->pos >> 1);
#if defined(DEBUG)
	printf("Parent\n");
	printf("h=%d, pos=%d\n", parent->height, parent->pos);
	Display("Node", parent->value, NODE_VALUE_SIZE);
	assert(_node_valid(parent));
	assert(parent->height == parent_height);
	assert(parent->pos == parent_pos);
	printf("-----------------------\n\n");
	//getchar();
#endif
}

void init_state(struct state_mt *state) {
	short i;
	state->stack_index = 0;
	//short max = (MERKLE_TREE_TREEHASH_SIZE > MERKLE_TREE_RETAIN_SIZE) ? MERKLE_TREE_TREEHASH_SIZE : MERKLE_TREE_RETAIN_SIZE;
	for(i = 0; i < MERKLE_TREE_TREEHASH_SIZE; i++) {
		state->treehash_state[i] = TREEHASH_FINISHED;
		state->treehash_used[i] = 1;
	}
	for(i = 0; i < MERKLE_TREE_K-1; i++) {
		state->retain_index[i] = 0;
	}

}

void _treehash_set_tailheight(struct state_mt *state, unsigned char h, unsigned char height) {
#if defined(DEBUG)
	assert(h < MERKLE_TREE_TREEHASH_SIZE);
#endif
	state->treehash_state[h] &= 0xE0; // clear previous height
	state->treehash_state[h] |= (TREEHASH_MASK & height); // set new height
}

unsigned char _treehash_get_tailheight(struct state_mt *state, unsigned char h) {
#if defined(DEBUG)
	assert(h < MERKLE_TREE_TREEHASH_SIZE);
#endif
	return (TREEHASH_MASK & state->treehash_state[h]);
}

void _treehash_state(struct state_mt *state, unsigned char h, enum TREEHASH_STATE th_state) {
	state->treehash_state[h] = th_state; // clean state
	#if defined(DEBUG)
	assert(_treehash_get_tailheight(state, h) == 0);
	#endif
}

void _treehash_initialize(struct state_mt *state, unsigned char h, short s) {
	state->treehash_seed[h] = s;
	_treehash_state(state, h, TREEHASH_NEW);
}

unsigned char _treehash_height(struct state_mt *state, unsigned char h) {
	unsigned char height = 0;
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

void _treehash_update(sponge_t *hash, sponge_t *priv, sponge_t *pubk, struct state_mt *state, const unsigned char h, struct node_t *node1, struct node_t *node2, const unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)]) {

	_create_leaf(hash, priv, pubk, node1, state->treehash_seed[h], seed);
	state->treehash_seed[h]++;
	_treehash_set_tailheight(state, h, 0);


	while(state->stack_index > 0 && _treehash_get_tailheight(state, h) == state->stack[state->stack_index - 1].height && (_treehash_get_tailheight(state, h) + 1) < h) {
	_stack_pop(state->stack, &state->stack_index, node2);
	_get_parent(hash, node2, node1, node1);
	_treehash_set_tailheight(state, h, _treehash_get_tailheight(state, h) + 1);
	}

	if(_treehash_get_tailheight(state, h) + 1 < h) {
		_stack_push(state->stack, &state->stack_index, node1);

		_treehash_state(state, h, TREEHASH_RUNNING);
	} else {
		//if((state->treehash_state[h] & TREEHASH_RUNNING) && (_treehash_get_tailheight(state, h) > 0 && _treehash_get_tailheight(state, h) < h)) {
		if((state->treehash_state[h] & TREEHASH_RUNNING) && (state->treehash_used[h] == 1) ) {
			*node2 = state->treehash[h];
			_get_parent(hash, node2, node1, node1);
			_treehash_set_tailheight(state, h, _treehash_get_tailheight(state, h) + 1);
		}
		state->treehash[h] = *node1;
		state->treehash_used[h] = 1;
		if (node1->height == h) {
			_treehash_state(state, h, TREEHASH_FINISHED);
		} else {
			_treehash_state(state, h, TREEHASH_RUNNING);
		}
	}
}

void _retain_push(struct state_mt *state, struct node_t *node) {
	short index = (1 << (MERKLE_TREE_HEIGHT - node->height - 1)) - (MERKLE_TREE_HEIGHT - node->height - 1) - 1 + (node->pos >> 1) - 1;
#if defined(DEBUG)
	assert(_node_valid(node));
	assert(state->retain_index[node->height - (MERKLE_TREE_HEIGHT - MERKLE_TREE_K)] == 0);
#endif
	state->retain[index] = *node;
	//state->retain_index++;
}

void _retain_pop(struct state_mt *state, struct node_t *node, short h) {
	//short i, index = state->retain_index-1;
	short hbar = (MERKLE_TREE_HEIGHT - h - 1);
#if defined(DEBUG)
	assert(h <= MERKLE_TREE_HEIGHT - 2);
	assert(h >= MERKLE_TREE_HEIGHT - MERKLE_TREE_K);
	assert(state->retain_index[h - (MERKLE_TREE_HEIGHT - MERKLE_TREE_K)] >= 0);
	assert(state->retain_index[h - (MERKLE_TREE_HEIGHT - MERKLE_TREE_K)] < (1 << hbar) - 1);
#endif
	short index = (1 << hbar) - hbar - 1 + state->retain_index[h - (MERKLE_TREE_HEIGHT - MERKLE_TREE_K)];
#if defined(DEBUG)
	assert(index >= 0);
	assert(index < MERKLE_TREE_RETAIN_SIZE);
#endif
	*node = state->retain[index];
	state->retain_index[h - (MERKLE_TREE_HEIGHT - MERKLE_TREE_K)]++;
	/*
	while(state->retain[index].height > h) {
		index--;
	}
	while(state->retain[index].height == state->retain[index-1].height) {
		index--;
	}
	*node = state->retain[index];
	for (i = index; i < state->retain_index; i++) {
		state->retain[i] = state->retain[i+1];
	}
	state->retain_index--;
	//*/
#if defined(DEBUG)
	assert(_node_valid(node));
	assert(node->height == h);
#endif
}

void _init_state(struct state_mt *state, struct node_t *node) {

	/*
	if (node->height == 0) {
		if (node->pos == 3*(1 << state->nextseed_height) && node->height < MERKLE_TREE_HEIGHT - MERKLE_TREE_K) {
			state->treehash_seed[state->nextseed_height] = node->pos;
			state->nextseed_height = state->nextseed_height + 1;
		}
	}//*/

	if(node->pos == 1 && node->height < MERKLE_TREE_HEIGHT) {
#if defined(DEBUG)
		assert(_node_valid(node));
		assert(node->pos == 1);
		assert(node->height < MERKLE_TREE_HEIGHT);
#endif
		state->auth[node->height] = *node;
	}
	if(node->pos == 3 && node->height < MERKLE_TREE_HEIGHT - MERKLE_TREE_K) {
#if defined(DEBUG)
		assert(_node_valid(node));
		assert(node->pos == 3);
		assert(node->height < MERKLE_TREE_HEIGHT - MERKLE_TREE_K);
#endif
		state->treehash[node->height] = *node;
		_treehash_initialize(state, node->height, node->pos);
		_treehash_state(state, node->height, TREEHASH_FINISHED); // state is finished since it has already computed the respective treehash node
	}
	if(node->pos >= 3 && ((node->pos & 1) == 1) && node->height >= MERKLE_TREE_HEIGHT - MERKLE_TREE_K) {
#if defined(DEBUG)
		assert(_node_valid(node));
		assert((node->height < MERKLE_TREE_HEIGHT - 1) && (node->height >= MERKLE_TREE_HEIGHT - MERKLE_TREE_K));
		assert(node->pos >= 3 && ((node->pos & 1) == 1));
#endif
		_retain_push(state, node);
	}
}

void mt_keygen(sponge_t *hash, sponge_t *priv, sponge_t *pubk, unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], struct node_t *node1, struct node_t *node2, struct state_mt *state, unsigned char pkey[NODE_VALUE_SIZE]) {
	short i, pos, index = 0;
	init_state(state);

	for(pos = 0; pos < (1 << MERKLE_TREE_HEIGHT); pos++) {
		_create_leaf(hash, priv, pubk, node1, pos, seed);
#if defined(DEBUG) && VERBOSE > 2
		printf("h=%d, pos=%d\n", node1->height, node1->pos);
		Display("Node: ", node1->value, NODE_VALUE_SIZE);
#endif
		_init_state(state, node1);
		while(index > 0 && state->keep[index - 1].height == node1->height) {
			_stack_pop(state->keep, &index, node2);
			_get_parent(hash, node2, node1, node1);
#if defined(DEBUG) && VERBOSE > 2 
			printf("h=%d, pos=%d\n", node1->height, node1->pos);
			Display("Node: ", node1->value, NODE_VALUE_SIZE);
#endif
			_init_state(state, node1);
		}
		_stack_push(state->keep, &index, node1);
	}
#if defined(DEBUG)
	print_auth(state);
	print_treehash(state);
	print_retain(state);
#endif
	for(i = 0; i < NODE_VALUE_SIZE; i++)
		pkey[i] = node1->value[i];
}

void _nextAuth(struct state_mt *state, const unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)], sponge_t *hash, sponge_t *priv, sponge_t *pubk, struct node_t *node1, struct node_t *node2, const short s) {
	short tau = MERKLE_TREE_HEIGHT - 1, h, min;

	while((s + 1) % (1 << tau) != 0)
		tau--;

#if defined(DEBUG)
	printf("NextAuth: s = %d, tau = %d\n", s, tau);
#endif

	if(tau < MERKLE_TREE_HEIGHT - 1 && (((s >> (tau + 1)) & 1) == 0))
		state->keep[tau] = state->auth[tau];

	if(tau == 0)
		_create_leaf(hash, priv, pubk, &state->auth[0], s, seed);
	else {
		_get_parent(hash, &state->auth[tau - 1], &state->keep[tau - 1], &state->auth[tau]);
		min = (tau - 1 < MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 1) ? tau - 1 : MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 1;
		for(h = 0; h <= min; h++) {

			//Do Treehash_h.pop()
			state->auth[h] = state->treehash[h];
			state->treehash_used[h] = 0; //Consumed, so not used
			/*
			if (_treehash_height(state, h) == 0) {
					_treehash_state(state, h, TREEHASH_FINISHED);
			} else {
				_treehash_set_tailheight(state, h, _treehash_get_tailheight(state, h) - 1);
			}
			//*/
			if((s + 1 + 3 * (1 << h)) < (1 << MERKLE_TREE_HEIGHT))
				_treehash_initialize(state, h, s + 1 + 3 * (1 << h));
			else
				_treehash_state(state, h, TREEHASH_FINISHED);
		}
		h = MERKLE_TREE_HEIGHT - MERKLE_TREE_K;
		while(h < tau) {
			_retain_pop(state, &state->auth[h], h);
			h = h + 1;
		}
	}
	// UPDATE
	short i, j, k;

	for(i = 0; i < (MERKLE_TREE_HEIGHT - MERKLE_TREE_K) / 2; i++) {
		min = TREEHASH_HEIGHT_INFINITY;
		k = MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 1; //TODO: confirmar se é esse mesmo o valor inicial
		for(j = MERKLE_TREE_HEIGHT - MERKLE_TREE_K - 1; j >= 0; j--) {
			if(_treehash_height(state, j) <= min) {
				min = state->treehash[j].height;
				k = j;
			}
		}
		if (!(state->treehash_state[k] & TREEHASH_FINISHED)) {
			_treehash_update(hash, priv, pubk, state, k, node1, node2, seed);
		}
	}
}

#if defined(DEBUG)

// Return the index of the authentication path for s-th leaf
void get_auth_index(short s, short auth_index[MERKLE_TREE_HEIGHT]) {
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

void _get_pkey(sponge_t *sponge, const struct node_t auth[MERKLE_TREE_HEIGHT], struct node_t *node, unsigned char *pkey) {
	short i, h;
	for(h = 0; h < MERKLE_TREE_HEIGHT; h++) {

#if defined(DEBUG)
		assert(_node_valid(node));
		assert(_node_valid(&auth[h]));
		assert(auth[h].height == h);
		assert(auth[h].height == node->height);
#endif		
		if(auth[h].pos >= node->pos) {
#if defined(DEBUG)
			assert(_node_brothers(node, &auth[h]));
#endif	
			_get_parent(sponge, node, &auth[h], node);
		}
		else {
#if defined(DEBUG)
			assert(_node_brothers(&auth[h], node));
#endif
			_get_parent(sponge, &auth[h], node, node);
		}
	}
#if defined(DEBUG)
	assert(_node_valid(node));
	assert(node->height == MERKLE_TREE_HEIGHT);
	assert(node->pos == 0);
#endif
	for(i = 0; i < NODE_VALUE_SIZE; i++)
		pkey[i] = node->value[i];
#if defined(DEBUG)		
	assert(memcmp(pkey, node->value, NODE_VALUE_SIZE) == 0);
#endif
}

/**
 * s     The pos-th winternitz private key
 * v     The pos-th winternitz public key used as a nonce for the hash H(v,M)
 *
 */

void merkletreeSign(struct state_mt *state, const unsigned char *seed, const unsigned char *v, const char *M, short len, sponge_t *hash, sponge_t *priv, sponge_t *pubk, unsigned char *h, short pos, struct node_t *node1, struct node_t *node2, unsigned char *sig, struct node_t authpath[MERKLE_TREE_HEIGHT]) {
	unsigned char i;
	unsigned char seedPos[LEN_BYTES(MERKLE_TREE_SEC_LVL)];
#if defined(DEBUG)
	assert((pos >= 0) && (pos < (1 << MERKLE_TREE_HEIGHT)));
#endif
	sinit(hash, MERKLE_TREE_SEC_LVL);
	absorb(hash, seed, NODE_VALUE_SIZE);
	absorb(hash, &pos, sizeof(pos));
	squeeze(hash, seedPos, LEN_BYTES(MERKLE_TREE_SEC_LVL)); // seed <- H(seed, pos)

	winternitzSig(seedPos, v, LEN_BYTES(WINTERNITZ_SEC_LVL), (const unsigned char *)M, len, priv, hash, h, sig);

	for(i = 0; i < MERKLE_TREE_HEIGHT; i++) {
		memcpy(&authpath[i].height, &state->auth[i].height,sizeof(short));//authpath[i].height = state->auth[i].height;
		memcpy(&authpath[i].pos, &state->auth[i].pos, sizeof(short));//authpath[i].pos = state->auth[i].pos;
		memcpy(authpath[i].value, state->auth[i].value, NODE_VALUE_SIZE);
	}

	if(pos <= (1 << MERKLE_TREE_HEIGHT)-2)
		_nextAuth(state, seed, hash, priv, pubk, node1, node2, pos);

}

/**
 * s     The pos-th Winternitz private key
 * v     The pos-th Winternitz public key used as a nonce for the hash H(v,M)
 *
 */

unsigned char merkletreeVerify(struct node_t authpath[MERKLE_TREE_HEIGHT], const unsigned char *v, const char *M, short len, sponge_t *hash, sponge_t *priv, sponge_t *pubk, unsigned char *h, short pos, const unsigned char *sig, unsigned char *x, struct node_t *currentLeaf, unsigned char merklePubKey[]) {

	unsigned char ok = 0;

	if (winternitzVer(v, LEN_BYTES(WINTERNITZ_SEC_LVL), (const unsigned char *)M, len, pubk, hash, h, sig, x) == 0)
		return 0;

	currentLeaf->height = 0;
	currentLeaf->pos = pos;
	memcpy(currentLeaf->value, v, NODE_VALUE_SIZE);

	_get_pkey(hash, authpath, currentLeaf, currentLeaf->value);

	ok = (memcmp(currentLeaf->value, merklePubKey, LEN_BYTES(MERKLE_TREE_SEC_LVL)) == 0);

#ifdef DEBUG
	if (ok == 1) {
		printf("Assinatura eh valida para posicao %d\n", pos);
	}
#endif // DEBUG

	return ok;
}


#if defined(MERKLE_TREE_SELFTEST) || defined(DEBUG)

#include <time.h>
#include "util.h"

int main(int argc, char *argv[]) {
	printf("\n Parameters:  SEC_LVL=%u, H=%u, K=%u, w=%u, node size=%u\n\n", MERKLE_TREE_SEC_LVL, MERKLE_TREE_HEIGHT, MERKLE_TREE_K, WINTERNITZ_W, NODE_VALUE_SIZE);

	// Execution variables
	unsigned char seed[LEN_BYTES(MERKLE_TREE_SEC_LVL)];
	unsigned char pkey[NODE_VALUE_SIZE];
	sponge_t sponges[3];
	struct node_t nodes[2];
	struct state_mt state;

	// Test variables
	clock_t elapsed;
	short j;
#if defined(DEBUG)
	short auth_index[MERKLE_TREE_HEIGHT];
	// Parameters for signing

	char M[] = "Hello, world!";
	unsigned char h1[LEN_BYTES(WINTERNITZ_SEC_LVL)],h2[LEN_BYTES(WINTERNITZ_SEC_LVL)]; // m-unsigned char message hash
	unsigned char sig[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
	unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];
	struct node_t currentLeaf;
	struct node_t authpath[MERKLE_TREE_HEIGHT];

#endif

#ifndef	_PYTHON_GENERATED
	// Count only execution variables
	printf("RAM total: %luB\n", (long unsigned int)(sizeof(seed) + sizeof(pkey) + sizeof(sponges) + sizeof(nodes) + sizeof(state)));
#endif
	for (j = 0; j < LEN_BYTES(MERKLE_TREE_SEC_LVL); j++) {
		seed[j] = 0xA0 ^ j; // sample private key, for debugging only
	}
#ifndef	_PYTHON_GENERATED
	Display("\n seed for keygen: ",seed,LEN_BYTES(MERKLE_TREE_SEC_LVL));
#endif

	//struct timeval t_start, t_end;
	short i, ntest = 1;
	elapsed = -clock();
	//gettimeofday(&t_start, NULL);
	for(i = 0; i < ntest; i++) {
		mt_keygen(&sponges[0] , &sponges[1], &sponges[2], seed, &nodes[0], &nodes[1], &state, pkey);

#if defined(DEBUG)
		Display(" Merkle Tree (pkey)\n", pkey, NODE_VALUE_SIZE);

		_create_leaf(&sponges[0], &sponges[1], &sponges[2], &currentLeaf, i, seed);
		merkletreeSign(&state, seed, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h1, i, &nodes[0], &nodes[1], sig, authpath);
		assert(merkletreeVerify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h2, i, sig, aux, &currentLeaf, pkey) == 1);

		printf("--------------- First authentication path ---------------\n");
		print_auth(&state);
		printf("------------------------------------\n");
		printf("Initial authentication path: Ok\n");
		for(j = 0; j < (1 << MERKLE_TREE_HEIGHT)-1; j++) {
			printf("\n--------------- s = %d ---------------\n", j);
			printf("Authentication path for %dth leaf\n", j + 1);

			_create_leaf(&sponges[0], &sponges[1], &sponges[2], &currentLeaf, j+1, seed);
			merkletreeSign(&state, seed, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h1, j+1, &nodes[0], &nodes[1], sig, authpath);
			assert(merkletreeVerify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &sponges[1], &sponges[2], h2, j+1, sig, aux, &currentLeaf, pkey) == 1);

			print_auth(&state);
			print_auth_index(auth_index);
			get_auth_index(j, auth_index);
			printf("------------------------------------\n");
		}

#endif
	}
	//gettimeofday(&t_end, NULL);
	elapsed += clock();
	//printf("Tempo de execucao %ld.%ldms\n", (t_end.tv_usec - t_start.tv_usec) / ntest / 1000, ((t_end.tv_usec - t_start.tv_usec) / ntest) % 1000);
	printf("KeyGen elapsed time: %.1f ms\n", 1000*(float)elapsed/CLOCKS_PER_SEC/ntest);

	return 0;
}
#endif
