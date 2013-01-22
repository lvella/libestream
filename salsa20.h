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
  union {
    uint32_t bit32[16];
    uint64_t bit64[8];
  } hash_input;
  char variant;
} salsa20_state;

void salsa20_init_key(salsa20_state *state, salsa20_variant variant,
		      const uint8_t *key, salsa20_key_size key_size);

void salsa20_init_iv(salsa20_state *iv_state, const salsa20_state *master,
		     const uint8_t *iv);

void salsa20_set_counter(salsa20_state *state, uint64_t counter);

void salsa20_extract(salsa20_state *state, uint8_t *stream);
