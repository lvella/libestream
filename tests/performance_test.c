/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdio.h>
#include <time.h>
#include "rabbit.h"
#include "sosemanuk.h"
#include "salsa20.h"
#include "hc-128.h"

static const unsigned char key[16] = {0x91, 0x28, 0x13, 0x29, 0x2E, 0x3D, 0x36, 0xFE, 0x3B, 0xFC, 0x62, 0xF1, 0xDC, 0x51, 0xC3, 0xAC};

static struct timespec ini, fin;

static double
timespecdiff(struct timespec *a, struct timespec *b)
{
  return a->tv_sec + a->tv_nsec / 1000000000.0
    - (b->tv_sec + b->tv_nsec / 1000000000.0);
}

static void
timing_start()
{
  clock_gettime(CLOCK_MONOTONIC_RAW, &ini);
}

static void
timing_end(const char *context) 
{
  clock_gettime(CLOCK_MONOTONIC_RAW, &fin);
  fprintf(stderr, "%s time: %f\n", context, timespecdiff(&fin, &ini));
}

static void
rc4_test() 
{
  void ksa(unsigned char state[], unsigned char key[], int len);
  void prga(unsigned char state[], unsigned char out[], int len);

  unsigned char state[256], stream[4096];
  int i; 

  timing_start();
  ksa(state,key,16);
  timing_end("RC4 key setup");

  fputs("RC4 lacks IV setup...\n", stderr);

  timing_start();
  for(i = 0; i < 10000; ++i) {
    prga(state, stream, 4096);
    fwrite(stream, 1, 4096, stdout);
  }
  timing_end("RC4 run");
}

static void
rabbit_test()
{
  rabbit_state master_state, state;
  unsigned char stream[4096];
  int i;

  timing_start();
  rabbit_init_key(&master_state, key);
  timing_end("Rabbit key setup");

  timing_start();
  rabbit_init_iv(&state, &master_state, key);
  timing_end("Rabbit IV setup (optional)");

  timing_start();
  for(i = 0; i < 10000; ++i) {
    int c;
    for(c = 0; c < 4096; c += 16)
      rabbit_extract(&state, &stream[c]);

    fwrite(stream, 1, 4096, stdout);
  }
  timing_end("Rabbit run");
}

static void
sosemanuk_test()
{
  sosemanuk_master_state mstate;
  sosemanuk_state ivstate;
  unsigned char stream[4096];
  int i;

  timing_start();
  sosemanuk_init_key(&mstate, key, 128);
  timing_end("Sosemanuk key setup");

  timing_start();
  sosemanuk_init_iv(&ivstate, &mstate, key);
  timing_end("Sosemanuk IV setup");

  timing_start();
  for(i = 0; i < 10000; ++i) {
    int c;
    for(c = 0; c < 4096; c += 16)
      sosemanuk_extract(&ivstate, &stream[c]);

    fwrite(stream, 1, 4096, stdout);
  }
  timing_end("Sosemanuk run");
}

static void
salsa20_test(salsa20_variant variant)
{
  salsa20_state mstate, ivstate;
  unsigned char stream[4096];
  int i;

  timing_start();
  salsa20_init_key(&mstate, variant, key, SALSA20_128_BITS);
  timing_end("Salsa20 key setup");

  timing_start();
  salsa20_init_iv(&ivstate, &mstate, key);
  timing_end("Salsa20 IV setup");

  timing_start();
  for(i = 0; i < 10000; ++i) {
    int c;
    for(c = 0; c < 4096; c += 64)
      salsa20_extract(&ivstate, &stream[c]);

    fwrite(stream, 1, 4096, stdout);
  }
  timing_end("Salsa20 run");
}

static void
hc128_test()
{
  hc128_state state;
  unsigned char stream[4096];
  int i;

  timing_start();
  hc128_init(&state, key, key);
  timing_end("HC-128 key and IV setup");

  timing_start();
  for(i = 0; i < 10000; ++i) {
    int c;
    for(c = 0; c < 4096; c += 4)
      hc128_extract(&state, &stream[c]);

    fwrite(stream, 1, 4096, stdout);
  }
  timing_end("HC-128 run");
}

int
main()
{
  rc4_test();
  rabbit_test();
  sosemanuk_test();
  hc128_test();
  fputs("Salsa20/8:\n", stderr);
  salsa20_test(SALSA20_8);
  fputs("Salsa20/12:\n", stderr);
  salsa20_test(SALSA20_12);
  fputs("Salsa20/20:\n", stderr);
  salsa20_test(SALSA20_20);
}
