#include "contiki.h"
#include "sys/clock.h"

#include <stdio.h>

//#include "benchmark.h"
//#include "benchmark.c"

#include "test.h"
#include "test.c"

#define PRINTF printf

/*---------------------------------------------------------------------------*/
PROCESS(bench_hashsig_process, "Bench Hash Signature");
AUTOSTART_PROCESSES(&bench_hashsig_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(bench_hashsig_process, ev, data)
{
  clock_time_t t1, t2;
  uint32_t i, benchs;
  clock_time_t prepare_time_ticks;
  clock_time_t start;
  int ret;

  PROCESS_BEGIN();  
  
  watchdog_stop();

  /* Prepare for energy measurements
  //  clock_wait(prepare_time_ticks); //waits for prepare_time_ticks of clock_timer (1 tick is ~ 8--10 ms)
  
  prepare_time_ticks = 500; // ~5s
  start = clock_time();
  while(clock_time() - start < (clock_time_t)prepare_time_ticks);
  //*/


//* Run Merkle Signature TESTS  
  ret = do_test(TEST_MERKLE_SIGN);
  printf("Test Merkle: %d \n", ret);
//*/

/* Run the specified benchmark
  benchs = 1;

  do_benchmark(BENCHMARK_PREPARE);  
  
  t1 = clock_time();
  
  //do_benchmark(BENCHMARK_PREPARE);
  //do_benchmark(BENCHMARK_WINTERNITZ_KEYGEN);
  //do_benchmark(BENCHMARK_SIGN);
  //do_benchmark(BENCHMARK_KEYGEN);
  //do_benchmark(BENCHMARK_VERIFY);

  t2 = clock_time();

  printf("Bench time = %lu (ticks) / %lu (ticks) / benchs = %u ms \n", t2 - t1, CLOCK_SECOND,(1000*(t2 - t1))/CLOCK_SECOND/benchs);
  //printf("Verify=%u", i);
//*/

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
