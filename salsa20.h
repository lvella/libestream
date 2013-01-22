#pragma once

#include <inttypes.h>

typedef enum {
  SALSA20_8 = 4,
  SALSA20_12 = 6,
  SALSA20_20 = 10
} salsa20_variant;

typedef enum {
  SALSA20_128_BITS,
  SALSA20_256_BITS
} salsa20_key_size;

typedef struct {
  uint32_t hash_input[16];
  char variant;
} salsa20_state;

