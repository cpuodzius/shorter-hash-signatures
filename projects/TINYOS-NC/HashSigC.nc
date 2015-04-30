#ifndef READ_ENERGY
#include "printf.h"
#include <stdio.h>
#endif

#ifdef RUN_BENCHS
#include "benchmark.h"
#else
#include "test.h"
#endif

module HashSigC {
  uses {
    interface Boot;
    interface Timer<TMilli>;
    interface Leds;
  }
}

implementation {

#ifdef RUN_BENCHS
	uint32_t benchs;

	void run_benchs() {
#ifndef READ_ENERGY
		uint32_t t1, t2;
		call Leds.set(7);

		printf("Starting benchs...\n");		  
		printf("\n Parameters: SEC_LVL=%u, H=%u, K=%u, W=%u, l1=%u, l2=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W, WINTERNITZ_l1, WINTERNITZ_l2);
		printfflush();
		
		t1 = call Timer.getNow();
#endif
		benchs = 1;
		/*/
		do_benchmark(BENCHMARK_AES_ENC, benchs);
		/*
		do_benchmark(BENCHMARK_HASH16_CALC, benchs);
		/*
		do_benchmark(BENCHMARK_HASH_CALC, benchs);
		/*
		do_benchmark(BENCHMARK_WINTERNITZ_KEYGEN,benchs);
		/*
		do_benchmark(BENCHMARK_WINTERNITZ_SIGN,benchs);
		/*
		do_benchmark(BENCHMARK_WINTERNITZ_VERIFY,benchs);
		/*
		do_benchmark(BENCHMARK_MSS_KEYGEN,benchs);
		/*
		do_benchmark(BENCHMARK_MSS_SIGN, benchs);
		/*/
		do_benchmark(BENCHMARK_MSS_VERIFY,benchs);
		//*/

#ifndef READ_ENERGY
		t2 = call Timer.getNow();
		printf("Elapsed: %lu ms\n", (t2 - t1));///benchs);
		
		call Leds.set(1);
		printf("DONE \n");
		printfflush();
#endif
	}

#else // RUN_TESTS

	void run_tests() {
		uint32_t ret;
		// Run Merkle Signature TESTS
		call Leds.set(7);

		printf("Starting tests...\n");
		ret = do_test(TEST_MSS_SIGN);
		//ret = do_test(TEST_AES_ENC);
		printf("Errors after tests: %lu\n", ret);
		printf("DONE \n");
		printfflush();
	
		call Leds.set(1);
	}
#endif

	event void Boot.booted() {
#ifndef READ_ENERGY
		call Leds.set(3);
#endif

		//do_benchmark(BENCHMARK_PREPARE, 1);
		//do_benchmark(BENCHMARK_MSS_KEYGEN,1);
		//do_benchmark(BENCHMARK_WINTERNITZ_SIGN,1);
		//do_benchmark(BENCHMARK_MSS_PREPARE_VERIFY,1);
		//do_benchmark(BENCHMARK_AES_CALC,1);


		call Timer.startOneShot(5000);
	}

	event void Timer.fired() {				
#ifdef RUN_BENCHS
		run_benchs();
#else
		run_tests();
#endif

		/* Test: Retain from ROM
		unsigned char buffer[16], b2[2];
		memcpy_P(buffer,&retain_values[0],16);
		memcpy_P(b2,&retain_pos[0],2);		
		
		printf("%02X\n",((unsigned char *)buffer)[0]);
		printf("%x\n",buffer[1]);
		printf("%x\n",buffer[2]);
		printf("%x\n",buffer[3]);
		printf("%x\n\n",buffer[4]);
		printf("%02x\n",b2[0]);
		printf("%02x\n",b2[1]);
		
		printfflush();
		//*/
	}
}


