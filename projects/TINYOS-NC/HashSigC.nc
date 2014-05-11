#include "printf.h"

#include <stdio.h>

/*
#include "benchmark.h"
#include "benchmark.c"
/*/
#include "test.h"
#include "test.c"
//*/

module HashSigC {
  uses {
    interface Boot;
    interface Timer<TMilli>;
    interface Leds;

  }
}

implementation {

	uint32_t t1, t2, ret, benchs;

	void run() {

		//call Leds.set(7);
		

		//* Run Merkle Signature TESTS
		printf("Starting tests...\n");
		ret = do_test(TEST_MSS_SIGN); 
		printf("Errors after tests: %lu\n", ret);

		/*/ //Run the specified benchmark
		benchs = 1;

		  
		printf("Starting benchs...\n");
		  
		printf("\n Parameters: SEC_LVL=%u, H=%u, K=%u, W=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W);
		  
		t1 = call Timer.getNow();
		  
		//do_benchmark(BENCHMARK_WINTERNITZ_KEYGEN);
		//do_benchmark(BENCHMARK_WINTERNITZ_SIGN);
		//do_benchmark(BENCHMARK_WINTERNITZ_VERIFY);

		//do_benchmark(BENCHMARK_MSS_KEYGEN);  
		do_benchmark(BENCHMARK_MSS_SIGN);
		//do_benchmark(BENCHMARK_MSS_VERIFY);

		t2 = call Timer.getNow();
		printf("Elapsed: %lu ms\n", t2 - t1);
		//*/
				
		//call Leds.set(1);
		printf("DONE \n");
		printfflush();
	}

	event void Boot.booted() {
		
		//do_benchmark(BENCHMARK_PREPARE);
		//do_benchmark(BENCHMARK_WINTERNITZ_SIGN);
		//do_benchmark(BENCHMARK_MSS_PREPARE_VERIFY);

		//printf("Oi!\n");
		//printfflush();
		//call Leds.led2On();
		call Timer.startOneShot(2000);
	}

	event void Timer.fired() {				
		run();
	}
}

