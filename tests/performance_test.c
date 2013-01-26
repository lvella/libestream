#include <stdio.h>
#include <time.h>
#include "rabbit.h"
#include "sosemanuk.h"
#include "salsa20.h"
#include "hc-128.h"

unsigned char key[16] = {0x91, 0x28, 0x13, 0x29, 0x2E, 0x3D, 0x36, 0xFE, 0x3B, 0xFC, 0x62, 0xF1, 0xDC, 0x51, 0xC3, 0xAC};

static void rc4_test() 
{
  void ksa(unsigned char state[], unsigned char key[], int len);
  void prga(unsigned char state[], unsigned char out[], int len);

  unsigned char state[256], stream[4096];
  int i; 

  ksa(state,key,16);

  for(i = 0; i < 10000; ++i) {
    prga(state, stream, 4096);
    fwrite(stream, 1, 4096, stdout);
  }
}

static void rabbit_test()
{
  rabbit_state state;
  unsigned char stream[4096];
  int i;

  rabbit_init_key(&state, key);

  for(i = 0; i < 10000; ++i) {
    int c;
    for(c = 0; c < 4096; c += 16)
      rabbit_extract(&state, &stream[c]);

    fwrite(stream, 1, 4096, stdout);
  }
}

static void sosemanuk_test()
{
    sosemanuk_master_state mstate;
    sosemanuk_init_key(&mstate, key, 128);

    sosemanuk_state ivstate;
    sosemanuk_init_iv(&ivstate, &mstate, key);

    unsigned char stream[4096];
    int i;

    for(i = 0; i < 10000; ++i) {
      int c;
      for(c = 0; c < 4096; c += 16)
	sosemanuk_extract(&ivstate, &stream[c]);

      fwrite(stream, 1, 4096, stdout);
    }
}

static void salsa20_test(salsa20_variant variant)
{
    salsa20_state mstate;
    salsa20_init_key(&mstate, variant, key, SALSA20_128_BITS);

    salsa20_state ivstate;
    salsa20_init_iv(&ivstate, &mstate, key);

    unsigned char stream[4096];
    int i;

    for(i = 0; i < 10000; ++i) {
      int c;
      for(c = 0; c < 4096; c += 64)
	salsa20_extract(&ivstate, &stream[c]);

      fwrite(stream, 1, 4096, stdout);
    }
}

static void hc128_test()
{
    hc128_state state;
    hc128_init(&state, key, key);

    unsigned char stream[4096];
    int i;

    for(i = 0; i < 10000; ++i) {
      int c;
      for(c = 0; c < 4096; c += 4)
	hc128_extract(&state, &stream[c]);

      fwrite(stream, 1, 4096, stdout);
    }
}

double
timespecdiff(struct timespec *a, struct timespec *b) {
  return a->tv_sec + a->tv_nsec / 1000000000.0
    - (b->tv_sec + b->tv_nsec / 1000000000.0);
}

int
main()
{
  struct timespec ini, fin;

  clock_gettime(CLOCK_MONOTONIC_RAW, &ini);
  rc4_test();
  clock_gettime(CLOCK_MONOTONIC_RAW, &fin);
  fprintf(stderr, "RC4 time: %f\n", timespecdiff(&fin, &ini));

  clock_gettime(CLOCK_MONOTONIC_RAW, &ini);
  rabbit_test();
  clock_gettime(CLOCK_MONOTONIC_RAW, &fin);
  fprintf(stderr, "Rabbit time: %f\n", timespecdiff(&fin, &ini));

  clock_gettime(CLOCK_MONOTONIC_RAW, &ini);
  sosemanuk_test();
  clock_gettime(CLOCK_MONOTONIC_RAW, &fin);
  fprintf(stderr, "Sosemanuk time: %f\n", timespecdiff(&fin, &ini));

  clock_gettime(CLOCK_MONOTONIC_RAW, &ini);
  hc128_test();
  clock_gettime(CLOCK_MONOTONIC_RAW, &fin);
  fprintf(stderr, "HC-128 time: %f\n", timespecdiff(&fin, &ini));

  clock_gettime(CLOCK_MONOTONIC_RAW, &ini);
  salsa20_test(SALSA20_8);
  clock_gettime(CLOCK_MONOTONIC_RAW, &fin);
  fprintf(stderr, "Salsa20/8 time: %f\n", timespecdiff(&fin, &ini));

  clock_gettime(CLOCK_MONOTONIC_RAW, &ini);
  salsa20_test(SALSA20_12);
  clock_gettime(CLOCK_MONOTONIC_RAW, &fin);
  fprintf(stderr, "Salsa20/12 time: %f\n", timespecdiff(&fin, &ini));

  clock_gettime(CLOCK_MONOTONIC_RAW, &ini);
  salsa20_test(SALSA20_20);
  clock_gettime(CLOCK_MONOTONIC_RAW, &fin);
  fprintf(stderr, "Salsa20/20 time: %f\n", timespecdiff(&fin, &ini));
}
