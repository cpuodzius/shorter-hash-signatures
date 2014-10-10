#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mss.h"

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
unsigned char dbg_seed[LEN_BYTES(MSS_SEC_LVL)];

unsigned char _node_valid_index(unsigned char height, short pos) {
	unsigned char valid_height = 0;
	short valid_pos = 0;
	if(height >= 0 && height <= MSS_HEIGHT) {
		valid_height = 1;
		if((pos >= 0) && (pos < (1 << (MSS_HEIGHT - height))))
			valid_pos = 1;
	}
	return (valid_height && valid_pos);
}

unsigned char _node_valid(const struct mss_node *node) {
	unsigned char valid_value_size = 0;
	if(sizeof(node->value) == LEN_BYTES(MSS_SEC_LVL))
		valid_value_size = 1;
	return (valid_value_size && _node_valid_index(node->height, node->index));
}

unsigned char _node_equal(const struct mss_node *node1, const struct mss_node *node2) {
	char equal = 0;
	if(node1->height == node2->height && node1->index == node2->index)
		equal = (memcmp(node1->value, node2->value, NODE_VALUE_SIZE) == 0);
	return equal;
}

unsigned char _is_left_node(const struct mss_node *node) {
	return ((node->index & 1) == 0);
}

unsigned char _is_right_node(const struct mss_node *node) {
	return ((node->index & 1) == 1);
}

unsigned char _node_brothers(const struct mss_node *left_node, const struct mss_node *right_node) {
	char brothers = 0;
	if(_node_valid(left_node) && _node_valid(right_node)) {
		if(left_node->height == right_node->height) {
			if((_is_left_node(left_node) && _is_right_node(right_node)) && (right_node->index - left_node->index == 1))
				brothers = 1;
		}
	}
	return brothers;
}

void print_auth(const struct state_mt *state) {
	unsigned char i;
	// Print Auth
	printf("\nAuthentication Path\n");
	for(i = 0; i < MSS_HEIGHT; i++) {
		printf("Node[%d, %d]", state->auth[i].height, state->auth[i].index);
		Display("", state->auth[i].value, NODE_VALUE_SIZE);
	}
}

void print_treehash(const struct state_mt *state) {
	unsigned char i;
	// Print Treehash
	printf("\nTreehash\n");
	for(i = 0; i < MSS_TREEHASH_SIZE; i++) {
		printf("Node[%d, %d]", state->treehash[i].height, state->treehash[i].index);
		Display("", state->treehash[i].value, NODE_VALUE_SIZE);
	}
}

void print_retain(const struct state_mt *state) {
	unsigned short j;
	unsigned char h;
	// Print Retain
	printf("\nRetain\n");
	for(h = MSS_HEIGHT - 2; h >= MSS_HEIGHT - MSS_K; h--) {
		for (j = (1 << (MSS_HEIGHT - h - 1)) - 2; j >= 0; j--) {
			unsigned short pos = 2*j + 3;
			unsigned short index = (1 << (MSS_HEIGHT - h - 1)) - (MSS_HEIGHT - h - 1) - 1 + (pos >> 1) - 1;
			printf("\tNode[%d, %d]", state->retain[index].height, state->retain[index].index);
			Display("", state->retain[index].value, NODE_VALUE_SIZE);
		}
	}
}

#endif

void _create_leaf(dm_t *f, sponge_t *pubk, struct mss_node *node, const unsigned short leaf_index, unsigned char seed[LEN_BYTES(MSS_SEC_LVL)]) {
	unsigned char sk[LEN_BYTES(MSS_SEC_LVL)];
#if defined(DEBUG)
	// seed must always be the same
	if(!dbg_seed_initialized) {
		dbg_seed_initialized = 1;
		memmove(dbg_seed, seed, LEN_BYTES(MSS_SEC_LVL));
	} else {
		assert(memcmp(dbg_seed, seed, LEN_BYTES(MSS_SEC_LVL)) == 0);
	}
	// leaf_index must be a valid
	assert(_node_valid_index(0, leaf_index));
	printf("\n--Leaf %d. \n", leaf_index);
#endif
    /*
	sinit(hash, MSS_SEC_LVL);
	absorb(hash, seed, NODE_VALUE_SIZE);
	absorb(hash, &leaf_index, sizeof(leaf_index));
	squeeze(hash, sk, LEN_BYTES(MSS_SEC_LVL)); // sk <- H(seed, leaf_index)
	//*/
	prg16(leaf_index, seed, sk); // sk := prg(seed,leaf_index)

	winternitz_keygen(sk, LEN_BYTES(WINTERNITZ_SEC_LVL), pubk, f, node->value);
	node->height = 0;
	node->index = leaf_index;

#if defined(DEBUG)
	assert(_node_valid(node));
	assert(node->height == 0);
	assert(node->index == leaf_index);
#endif
}

void _stack_push(struct mss_node stack[MSS_KEEP_SIZE], unsigned short *index, struct mss_node *node) {
#if defined(DEBUG)
	assert(*index >= 0);
	assert(_node_valid(node));
	const unsigned short prior_index = *index;
	unsigned short i;
	printf("----- _stack_push -----\n\n");
	printf("Stack before push:");
	if(*index == 0)
		printf(" empty\n");
	else
		printf("\n");
	for(i = *index - 1; i >= 0; i--) {
		printf("\nStack node: %d\n", i);
		printf("h=%d, pos=%d\n", stack[i].height, stack[i].index);
		Display("Node", stack[i].value, NODE_VALUE_SIZE);
	}
	printf("\nNode to push\n");
	printf("h=%d, pos=%d\n", node->height, node->index);
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
		printf("h=%d, pos=%d\n", stack[i].height, stack[i].index);
		Display("Node", stack[i].value, NODE_VALUE_SIZE);
	}
	assert(*index == prior_index + 1);
	printf("-----------------------\n");
#endif
}

void _stack_pop(struct mss_node stack[MSS_KEEP_SIZE], unsigned short *index, struct mss_node *node) {
#if defined(DEBUG)
	assert(*index > 0);
	const unsigned short prior_index = *index;
#endif
	*node = stack[--*index];
#if defined(DEBUG)
	assert(_node_valid(node));
	assert(*index == prior_index - 1);
#endif
}

void _get_parent(dm_t *hash, const struct mss_node *left_child, const struct mss_node *right_child, struct mss_node *parent) {
#if defined(DEBUG)
	assert(_node_valid(left_child));
	assert(_node_valid(right_child));
	// left_child and right_child must have the same height and be below the root
	assert(left_child->height < MSS_HEIGHT);
	assert(right_child->height < MSS_HEIGHT);
	assert(left_child->height == right_child->height);
	// left_child and right_child must be brothers
	// left_child->index must be even and right_child->index must be odd
	assert(_is_left_node(left_child));
	assert(_is_right_node(right_child));
	assert(right_child->index == left_child->index + 1);
	const unsigned char parent_height = right_child->height + 1;
	const unsigned short parent_pos = (right_child->index / 2);
	/*
	printf("----- _get_parent -----\n\n");
	printf("Left Child\n");
	printf("h=%d, pos=%d\n", left_child->height, left_child->index);
	Display("Node", left_child->value, NODE_VALUE_SIZE);
	printf("Right Child\n");
	printf("h=%d, pos=%d\n", right_child->height, right_child->index);
	Display("Node", right_child->value, NODE_VALUE_SIZE);
	getchar();
	//*/
#endif

    hash32(hash, left_child->value, right_child->value, parent->value);

	parent->height = left_child->height + 1;
	parent->index = (left_child->index >> 1);
#ifdef DEBUG
	printf("Parent\n");
	printf("h=%d, index=%d\n", parent->height, parent->index);
	Display("Node", parent->value, NODE_VALUE_SIZE);
	assert(_node_valid(parent));
	assert(parent->height == parent_height);
	assert(parent->index == parent_pos);
	printf("-----------------------\n\n");
#endif
}

void init_state(struct state_mt *state) {

	state->stack_index = 0;

	memset(state->treehash_state, TREEHASH_FINISHED, MSS_TREEHASH_SIZE);
	memset(state->retain_index, 0, (MSS_K-1)*sizeof(unsigned short));
}

void _treehash_set_tailheight(struct state_mt *state, unsigned char h, unsigned char height) {
#if defined(DEBUG)
	assert(h < MSS_TREEHASH_SIZE);
#endif
	state->treehash_state[h] &= 0xE0; // clear previous height
	state->treehash_state[h] |= (TREEHASH_MASK & height); // set new height
}

unsigned char _treehash_get_tailheight(struct state_mt *state, unsigned char h) {
#if defined(DEBUG)
	assert(h < MSS_TREEHASH_SIZE);
#endif
	return (TREEHASH_MASK & state->treehash_state[h]);

}

void _treehash_state(struct state_mt *state, unsigned char h, enum TREEHASH_STATE th_state) {

#if defined(DEBUG)
	assert(h >= 0 && h < MSS_TREEHASH_SIZE);
#endif
	state->treehash_state[h] = th_state; // set state
#if defined(DEBUG)
	assert(_treehash_get_tailheight(state, h) == 0);
#endif
}

void _treehash_initialize(struct state_mt *state, unsigned char h, unsigned short s) {
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

void _treehash_update(dm_t *hash, sponge_t *pubk, struct state_mt *state, const unsigned char h, struct mss_node *node1, struct mss_node *node2,
                      unsigned char seed[LEN_BYTES(MSS_SEC_LVL)]) {

	if(h < MSS_TREEHASH_SIZE-1 && (state->treehash_seed[h] >= 11*(1<<h)) && (((state->treehash_seed[h] - 11*(1<<h)) % (1<<(2+h))) == 0) ) {
		node1->height = 0;
		node1->index = state->treehash_seed[h];
		memcpy(node1->value, state->store[h].value, NODE_VALUE_SIZE);
#ifdef MSS_SELFTEST
		//printf("Treehash %d recovered node %d \n",h,state->treehash_seed[h]);
#endif
	} else {
#ifdef MSS_SELFTEST
		//printf("Calc leaf in treehash%d: %d \n",h,state->treehash_seed[h]);
#endif
		_create_leaf(hash, pubk, node1, state->treehash_seed[h], seed);
	}

	if( h > 0 && (state->treehash_seed[h] >= 11*(1<<(h-1))) && ((state->treehash_seed[h]-11*(1<<(h-1))) % (1<<(h+1)) ==0) ) {
		state->store[h-1].height = 0;
		state->store[h-1].index = state->treehash_seed[h];
		memcpy(state->store[h-1].value,node1->value,NODE_VALUE_SIZE);
#ifdef MSS_SELFTEST
		//printf("Treehash %d stored node %d \n",h,state->treehash_seed[h]);
#endif
	}

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
		if((state->treehash_state[h] & TREEHASH_RUNNING) && (node1->index & 1)) { // if treehash *is used*
			*node2 = state->treehash[h];
			_get_parent(hash, node2, node1, node1);
			_treehash_set_tailheight(state, h, _treehash_get_tailheight(state, h) + 1);
		}
		state->treehash[h] = *node1;
		if (node1->height == h) {
			_treehash_state(state, h, TREEHASH_FINISHED);
		} else {
			_treehash_state(state, h, TREEHASH_RUNNING);
		}
	}
}

void _retain_push(struct state_mt *state, struct mss_node *node) {
#ifdef MSS_CALC_RETAIN
	unsigned short index = (1 << (MSS_HEIGHT - node->height - 1)) - (MSS_HEIGHT - node->height - 1) - 1 + (node->index >> 1) - 1;
#if defined(DEBUG)
	assert(_node_valid(node));
	assert(state->retain_index[node->height - (MSS_HEIGHT - MSS_K)] == 0);
#endif
	state->retain[index] = *node;
#endif // MSS_CALC_RETAIN
}

void _retain_pop(struct state_mt *state, struct mss_node *node, unsigned short h) {
	unsigned char hbar = (MSS_HEIGHT - h - 1);
#if defined(DEBUG)
	assert(h <= MSS_HEIGHT - 2);
	assert(h >= MSS_HEIGHT - MSS_K);
	assert(state->retain_index[h - (MSS_HEIGHT - MSS_K)] >= 0);
	assert(state->retain_index[h - (MSS_HEIGHT - MSS_K)] < (1 << hbar) - 1);
#endif
	unsigned short index = (1 << hbar) - hbar - 1 + state->retain_index[h - (MSS_HEIGHT - MSS_K)];
#if defined(DEBUG)
	assert(index >= 0);
	assert(index < MSS_RETAIN_SIZE);
#endif

#ifndef MSS_CALC_RETAIN
	memcpy_P(&node->height,&retain_height[index],1);
	memcpy_P(&node->index,&retain_pos[index],1);
	memcpy_P(node->value,&retain_values[index],NODE_VALUE_SIZE);
#else
	*node = state->retain[index];
#endif
	state->retain_index[h - (MSS_HEIGHT - MSS_K)]++;

#if defined(DEBUG)
	assert(_node_valid(node));
	assert(node->height == h);
#endif
}

void _init_state(struct state_mt *state, struct mss_node *node) {

	if(node->index == 1 && node->height < MSS_HEIGHT) {
#if defined(DEBUG)
		assert(_node_valid(node));
		assert(node->index == 1);
		assert(node->height < MSS_HEIGHT);
#endif
		state->auth[node->height] = *node;
	}
	if(node->index == 3 && node->height < MSS_HEIGHT - MSS_K) {
#if defined(DEBUG)
		assert(_node_valid(node));
		assert(node->index == 3);
		assert(node->height < MSS_HEIGHT - MSS_K);
#endif
		state->treehash[node->height] = *node;
		_treehash_initialize(state, node->height, node->index);
		_treehash_state(state, node->height, TREEHASH_FINISHED); // state is finished since it has already computed the respective treehash node
	}
	if(node->index >= 3 && ((node->index & 1) == 1) && node->height >= MSS_HEIGHT - MSS_K) {
#if defined(DEBUG)
		assert(_node_valid(node));
		assert((node->height < MSS_HEIGHT - 1) && (node->height >= MSS_HEIGHT - MSS_K));
		assert(node->index >= 3 && ((node->index & 1) == 1));
#endif
		_retain_push(state, node);
	}
}

void mss_keygen(dm_t *hash, sponge_t *pubk, unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], struct mss_node *node1, struct mss_node *node2, struct state_mt *state, unsigned char pkey[NODE_VALUE_SIZE]) {
	unsigned short i, pos, index = 0;
	init_state(state);

	for(pos = 0; pos < (1 << MSS_HEIGHT); pos++) {
        _create_leaf(hash, pubk, node1, pos, seed);

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

void _nextAuth(struct state_mt *state, struct mss_node *current_leaf, unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], dm_t *hash, sponge_t *pubk, struct mss_node *node1, struct mss_node *node2, const unsigned short s) {
	short tau = MSS_HEIGHT - 1, min, h, i, j, k;

	while((s + 1) % (1 << tau) != 0)
		tau--;

#if defined(DEBUG)
	printf("NextAuth: s = %d, tau = %d, nextleaf = %d\n", s, tau, s + 1);
#endif

	if(tau < MSS_HEIGHT - 1 && (((s >> (tau + 1)) & 1) == 0))
		state->keep[tau] = state->auth[tau];

	if(tau == 0) { // next leaf is a right node
		state->auth[0] = *current_leaf; // Leaf was already computed because our nonce
	} else { // next leaf is a left node
		_get_parent(hash, &state->auth[tau - 1], &state->keep[tau - 1], &state->auth[tau]);
		min = (tau - 1 < MSS_HEIGHT - MSS_K - 1) ? tau - 1 : MSS_HEIGHT - MSS_K - 1;
		for(h = 0; h <= min; h++) {

			//Do Treehash_h.pop()
			state->auth[h] = state->treehash[h];

			if((s + 1 + 3 * (1 << h)) < (1 << MSS_HEIGHT))
				_treehash_initialize(state, h, s + 1 + 3 * (1 << h));
			else
				_treehash_state(state, h, TREEHASH_FINISHED);
		}
		h = MSS_HEIGHT - MSS_K;
		while(h < tau) {
			_retain_pop(state, &state->auth[h], h);
			h = h + 1;
		}
	}
	// UPDATE
	for(i = 0; i < (MSS_HEIGHT - MSS_K) / 2; i++) {
		min = TREEHASH_HEIGHT_INFINITY;
		k = MSS_HEIGHT - MSS_K - 1;
		for(j = MSS_HEIGHT - MSS_K - 1; j >= 0; j--) {
			if(_treehash_height(state, j) <= min) {
				min = state->treehash[j].height;
				k = j;
			}
		}
		if (!(state->treehash_state[k] & TREEHASH_FINISHED)) {
			_treehash_update(hash, pubk, state, k, node1, node2, seed);
		}
	}
}

#if defined(DEBUG)

// Return the index of the authentication path for s-th leaf
void get_auth_index(unsigned short s, unsigned short auth_index[MSS_HEIGHT]) {
	unsigned char h;
	for(h = 0; h < MSS_HEIGHT; h++) {
		if(s % 2 == 0)
			auth_index[h] = s + 1;
		else

			auth_index[h] = s - 1;
		s >>= 1;
	}
}

void print_auth_index(unsigned short auth_index[MSS_HEIGHT - 1]) {
	printf("Expected index:\n");
	unsigned char h;
	for(h = MSS_HEIGHT - 1; h >= 0; h--)
		printf("\th = %d : n[%d][%d]\n", h, h, auth_index[h]);
}

#endif

void _get_pkey(dm_t *hash, const struct mss_node auth[MSS_HEIGHT], struct mss_node *node, unsigned char *pkey) {
	unsigned char i, h;
	for(h = 0; h < MSS_HEIGHT; h++) {

#if defined(DEBUG)
		assert(_node_valid(node));
		assert(_node_valid(&auth[h]));
		assert(auth[h].height == h);
		assert(auth[h].height == node->height);
#endif
		if(auth[h].index >= node->index) {
#if defined(DEBUG)
			assert(_node_brothers(node, &auth[h]));
#endif
			_get_parent(hash, node, &auth[h], node);
		}
		else {
#if defined(DEBUG)
			assert(_node_brothers(&auth[h], node));
#endif
			_get_parent(hash, &auth[h], node, node);
		}
	}
#if defined(DEBUG)
	assert(_node_valid(node));
	assert(node->height == MSS_HEIGHT);
	assert(node->index == 0);
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

void mss_sign(struct state_mt *state, unsigned char *seed, struct mss_node *leaf, const char *M, unsigned short len,
              mmo_t *mmo, dm_t *f, unsigned char *h, unsigned short leaf_index, struct mss_node *node1, struct mss_node *node2, unsigned char *sig, struct mss_node authpath[MSS_HEIGHT]) {
	unsigned char i;
	unsigned char sk[LEN_BYTES(MSS_SEC_LVL)];
#if defined(DEBUG)
	assert((leaf_index >= 0) && (leaf_index < (1 << MSS_HEIGHT)));
#endif


    if(leaf_index % 2 == 0) {
#ifdef MSS_SELFTEST
		//printf("Calc leaf in sign: %d \n",leaf_index);
#endif
        _create_leaf(f, mmo, leaf, leaf_index, seed);
    } else {
        leaf->height = 0;
        leaf->index = leaf_index;
        memcpy(leaf->value, authpath[0].value, NODE_VALUE_SIZE);
    }

    /*
	sinit(hash, MSS_SEC_LVL);
	absorb(hash, seed, NODE_VALUE_SIZE);
	absorb(hash, &leaf_index, sizeof(leaf_index));
	squeeze(hash, sk, LEN_BYTES(MSS_SEC_LVL)); // sk := hash(seed,leaf_index)
	//*/
    prg16(leaf_index, seed, sk); // sk := prg16(seed,leaf_index)

	winternitz_sign(sk, leaf->value, LEN_BYTES(WINTERNITZ_N), (const char *)M, len, mmo, f, h, sig);

	for(i = 0; i < MSS_HEIGHT; i++) {
		authpath[i].height = state->auth[i].height;
		authpath[i].index = state->auth[i].index;
		memcpy(authpath[i].value, state->auth[i].value, NODE_VALUE_SIZE);
	}

	if(leaf_index <= (1 << MSS_HEIGHT)-2)
		_nextAuth(state, leaf, seed, f, mmo, node1, node2, leaf_index);
}

/**
 * s     The leaf_index-th Winternitz private key
 * v     The leaf_index-th Winternitz public key used as a nonce for the hash H(v,M)
 *
 */

unsigned char mss_verify(struct mss_node authpath[MSS_HEIGHT], const unsigned char *v, const char *M, unsigned short len,
                         mmo_t *hash, dm_t *f, unsigned char *h, unsigned short leaf_index, const unsigned char *sig, unsigned char *x, struct mss_node *currentLeaf, unsigned char merklePubKey[]) {


	if (winternitz_verify(v, LEN_BYTES(WINTERNITZ_N), (const char *)M, len, hash, f, h, sig, x) == WINTERNITZ_ERROR) {
		return MSS_ERROR;
	}

	currentLeaf->height = 0;
	currentLeaf->index = leaf_index;
	memcpy(currentLeaf->value, v, NODE_VALUE_SIZE);

	_get_pkey(f, authpath, currentLeaf, currentLeaf->value);

	if (memcmp(currentLeaf->value, merklePubKey, LEN_BYTES(MSS_SEC_LVL)) == 0) {
#ifdef DEBUG
		printf("Assinatura eh valida para folha %d\n", leaf_index);
#endif // DEBUG
		return MSS_OK;
	}

	return MSS_ERROR;
}


#if defined(MSS_SELFTEST) || defined(DEBUG)

#include <time.h>
#include "util.h"
#include "test.h"

int main(int argc, char *argv[]) {
    printf("\n Parameters:  sec lvlH=%u, H=%u, K=%u, W=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W);

    do_test(TEST_MSS_SIGN);

#if defined(DEBUG)
	// Execution variables
	unsigned char seed[LEN_BYTES(MSS_SEC_LVL)];
	unsigned char pkey[NODE_VALUE_SIZE];
	sponge_t sponges[2];
	dm_t f;
	struct mss_node nodes[2];
	struct state_mt state;

	// Test variables
	clock_t elapsed;
	unsigned short j;

	unsigned short auth_index[MSS_HEIGHT];
	// Parameters for signing

	char M[] = "Hello, world!";
	unsigned char h1[LEN_BYTES(WINTERNITZ_SEC_LVL)],h2[LEN_BYTES(WINTERNITZ_SEC_LVL)]; // m-unsigned char message hash
	unsigned char sig[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)];
	unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];
	struct mss_node currentLeaf;
	struct mss_node authpath[MSS_HEIGHT];

	// Count only execution variables
	printf("RAM total: %luB\n", (long unsigned int)(sizeof(seed) + sizeof(pkey) + sizeof(sponges) + sizeof(nodes) + sizeof(state) + sizeof(f)));

	for (j = 0; j < LEN_BYTES(MSS_SEC_LVL); j++) {
		seed[j] = 0xA0 ^ j; // sample private key, for debugging only
	}
	Display("\n seed for keygen: ",seed,LEN_BYTES(MSS_SEC_LVL));

	unsigned short i, ntest = 1;
	elapsed = -clock();
	for(i = 0; i < ntest; i++) {
		mss_keygen(&f , &sponges[1], seed, &nodes[0], &nodes[1], &state, pkey);

		Display(" Merkle Tree (pkey)\n", pkey, NODE_VALUE_SIZE);

		mss_sign(&state, seed, &currentLeaf, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &f, h1, i, &nodes[0], &nodes[1], sig, authpath);
		assert(mss_verify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &f, h2, i, sig, aux, &currentLeaf, pkey) == MSS_OK);

		printf("--------------- First authentication path ---------------\n");
		print_auth(&state);
		printf("------------------------------------\n");
		printf("Initial authentication path: Ok\n");
		for(j = 0; j < (1 << MSS_HEIGHT)-1; j++) {
			printf("\n--------------- s = %d ---------------\n", j);
			printf("Authentication path for %dth leaf\n", j + 1);

			mss_sign(&state, seed, &currentLeaf, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &f, h1, j+1, &nodes[0], &nodes[1], sig, authpath);
			assert(mss_verify(authpath, currentLeaf.value, M, LEN_BYTES(WINTERNITZ_SEC_LVL), &sponges[0], &f, h2, j+1, sig, aux, &currentLeaf, pkey) == MSS_OK);

			print_auth(&state);
			print_auth_index(auth_index);
			get_auth_index(j, auth_index);
			printf("------------------------------------\n");
		}
	}
	elapsed += clock();
	printf("Elapsed time: %.1f ms\n", 1000*(float)elapsed/CLOCKS_PER_SEC/ntest);

#endif // DEBUG

    printf("\n Parameters:  sec lvl=%u, H=%u, K=%u, W=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W);

	return 0;
}
#endif
