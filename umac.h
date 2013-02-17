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
