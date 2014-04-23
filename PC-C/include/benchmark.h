#ifndef __BENCHMARK
#define __BENCHMARK

#include "sponge.h"
#include "merkletree.h"

enum BENCHMARK {
	BENCHMARK_PREPARE,
	BENCHMARK_KEYGEN,
	BENCHMARK_SIGN,
	BENCHMARK_VERIFY,
	BENCHMARK_WINTERNITZ_KEYGEN,
	BENCHMARK_HASH_CALC
};

void do_benchmark(enum BENCHMARK phase);

#endif // __BENCHMARK
