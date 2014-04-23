#ifndef __TEST
#define __TEST

#include "sponge.h"
#include "merkletree.h"

enum TEST {
	TEST_MERKLE_SIGN,
};

#define TEST_OK 1
#define TEST_FALSE 0

int do_test(enum TEST operation);

#endif // __TEST
