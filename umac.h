#pragma once

#include <inttypes.h>

typedef struct
{
  uint64_t v[2]; /* Big endian; 0: most significant; 1: least significant */
} uint128;

typedef struct
{
  uint32_t l1key[268];
  struct {
    uint64_t k64;
    uint128 k128;
  } l2key[4];
  uint64_t l3key1[32];
  uint32_t l3key2[4];
} uhash_128_key;

typedef struct
{
  uint32_t buffer[256];
  size_t byte_len;
  uint128 l2_partial[4];
} uhash_128_state;

void uhash_128_init(uhash_128_state *state);
void uhash_128_update(uhash_128_key *key, uhash_128_state *state,
		      uint8_t *string, size_t len);
void uhash_128_finish(uhash_128_key *key, uhash_128_state *state, uint8_t *out);

void uhash_128_full(uhash_128_key *key, uint8_t *string, size_t len);
