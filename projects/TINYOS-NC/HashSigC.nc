#ifndef READ_ENERGY
#include "printf.h"
#include <stdio.h>
#endif

//*
#include "benchmark.h"
/*/
#include "test.h"
//*/

module HashSigC {
  uses {
    interface Boot;
    interface Timer<TMilli>;
    interface Leds;

  }
}

implementation {

#ifndef READ_ENERGY
	uint32_t t1, t2, ret;
#endif

	uint32_t benchs;

	void run() {

		/* Run Merkle Signature TESTS
		printf("Starting tests...\n");
		ret = do_test(TEST_MSS_SIGN); 
		printf("Errors after tests: %lu\n", ret);
		printf("DONE \n");
		printfflush();		

		/*/ //Run the specified benchmark
		
#ifndef READ_ENERGY
		call Leds.set(7);

		printf("Starting benchs...\n");
		  
		printf("\n Parameters: SEC_LVL=%u, H=%u, K=%u, W=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W);
		  
		t1 = call Timer.getNow();
#endif
		benchs = 1;
		/*
		benchs = 1000;
		do_benchmark(BENCHMARK_AES_CALC, benchs);
		/*
		benchs = 1000;
		do_benchmark(BENCHMARK_HASH_CALC, benchs);
		/*
		do_benchmark(BENCHMARK_WINTERNITZ_KEYGEN,benchs);
		/*
		do_benchmark(BENCHMARK_WINTERNITZ_SIGN,benchs);
		/*
		do_benchmark(BENCHMARK_WINTERNITZ_VERIFY,benchs);
		/*
		do_benchmark(BENCHMARK_MSS_KEYGEN,benchs);  
		/*/
		do_benchmark(BENCHMARK_MSS_SIGN, benchs);
		/*
		do_benchmark(BENCHMARK_MSS_VERIFY,benchs);
		/*/

#ifndef READ_ENERGY
		t2 = call Timer.getNow();
		printf("Elapsed: %lu ms\n", (t2 - t1)/benchs);
		
		call Leds.set(1);
		printf("DONE \n");
		printfflush();
#endif
		//*/		
	}

	event void Boot.booted() {
		
		do_benchmark(BENCHMARK_PREPARE, 1);
		//do_benchmark(BENCHMARK_WINTERNITZ_SIGN,1);
		//do_benchmark(BENCHMARK_MSS_PREPARE_VERIFY,1);
		//do_benchmark(BENCHMARK_AES_CALC,1);

		//call Leds.led2On();
		call Timer.startOneShot(3000);
	}

	event void Timer.fired() {				
		run();
	}
}

