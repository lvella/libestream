#include <stdio.h>
#include <time.h>
#include "rabbit.h"

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

  rabbit_init_master(&state, key);

  for(i = 0; i < 10000; ++i) {
    int c;
    for(c = 0; c < 4096; c += 16)
      rabbit_extract(&state, &stream[c]);

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
}
