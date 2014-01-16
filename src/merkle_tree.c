#include <stdio.h>
#include <stdlib.h>
#include <math.h>


#define SEC_LVL						8
//#define SEC_LVL						128
#define MERKLE_TREE_HEIGHT			5

#define	N_NODES	((1 << (MERKLE_TREE_HEIGHT + 1)) - 1)
#define NODE_VALUE_SIZE (SEC_LVL >> 3)		// each value element is a byte

typedef unsigned char byte;

struct node_t {
	short height, pos;
	byte value[NODE_VALUE_SIZE];		// node's value for auth path	
};

struct merkle_t {
	short height;
	struct node_t node[N_NODES];
};

void stack_push(struct node_t stack[], short *index, struct node_t node) {
	stack[*index++] = node;
}

int get_rand() {
	return rand();
}

void _print_node(struct node_t node) {
	short i;
	printf("[");
	for(i = 0; i < NODE_VALUE_SIZE; i++) {
		printf("%X", (node.value[i] >> 4) & 0x0F);
		printf("%X", node.value[i] & 0x0F);
	}
	printf("]");
}

struct node_t _get_node(struct merkle_t *tree, short height, short pos) {
	short index = 1;

	short i;
	for(i = 0; i < tree->height - height; i++)
		index <<= 1;
	index--;

	return tree->node[index + pos];
}

void print_merkle_tree(struct merkle_t *tree) {
	short i, j, k, n;

	short blank = 1;
	for(i = 0; i < tree->height; i++)
		blank <<= 1;
	blank--;

	n = 1;						// number of nodes in the current height
	for(i = 0; i <= tree->height; i++) {

		for(j = 0; j < n; j++) {
			for(k = 0; k < blank; k++)
				printf(" ");
			_print_node(_get_node(tree, tree->height - i, j));
			if(j == n - 1)
				break;
			else {
				for(k = 0; k <= blank; k++)
					printf(" ");
			}
		}
		printf("\n");

		n <<= 1;
		blank >>= 1;
	}
}

void _init_node(struct node_t *node, short index, short tree_height) {
	short i, j;

	for(i = 0; i < SEC_LVL / 8; i++)
		node->value[i] = get_rand();

	i = 1;
	j = 0;
	while(i << 1 <= index + 1) {
		i <<= 1;
		j++;
	}
	i--;

	node->height = tree_height - j;
	node->pos = index - i;
}

int main() {
	int i;

	struct node_t nodes[N_NODES];

	for(i = 0; i < N_NODES; i++)
		_init_node(nodes, i, MERKLE_TREE_HEIGHT);

	struct merkle_t tree;

	tree.height = (short) MERKLE_TREE_HEIGHT;
	for(i = 0; i < N_NODES; i++)
		tree.node[i] = nodes[i];

	print_merkle_tree(&tree);
	printf("\n\n\n");
	for(i = 0; i < N_NODES; i++)
		_print_node(nodes[i]);

	return 0;	
}
