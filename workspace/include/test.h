#ifndef __TEST
#define __TEST

#include "mss.h"
#include "util.h"

enum TEST {
	TEST_MSS_SIGN,
};

#define TEST_OK 1
#define TEST_FALSE 0

int do_test(enum TEST operation);

#endif // __TEST
