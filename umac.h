#pragma once

#include <stddef.h>
#include <inttypes.h>
#include "buffered.h"

/* Internally used structs. */

typedef struct
{
  uint64_t v[2]; /* Big endian; 0: most significant; 1: least significant */
} uint128;

typedef struct
{
  uint64_t k64;
  uint128 k128;
} l2_key;

typedef struct
{
  uint128 y;
  uint64_t tmp;
} l2_state;

/* Public interface: */

#define UHASH_BITS(bits)						\
  typedef struct							\
  {									\
    uint32_t l1key[256 + ((bits)/32-1) * 4];				\
    l2_key l2key[(bits)/32];						\
    uint64_t l3key1[(bits)/4];						\
    uint32_t l3key2[(bits)/32];						\
  } uhash_##bits##_key;							\
									\
  typedef struct							\
  {									\
    uint32_t buffer[256];						\
    size_t byte_len;							\
    l2_state l2_partial[(bits)/32];					\
  } uhash_##bits##_state;						\
									\
  void uhash_##bits##_key_setup(const cipher_attributes *cipher,	\
				void *buffered_state,			\
				uhash_##bits##_key *key);		\
  									\
  void uhash_##bits##_init(uhash_##bits##_state *state);		\
  void uhash_##bits##_update(const uhash_##bits##_key *key,		\
			     uhash_##bits##_state *state,		\
			     const uint8_t *string, size_t len);	\
  void uhash_##bits##_finish(const uhash_##bits##_key *key,		\
			     uhash_##bits##_state *state,		\
			     uint8_t *out);

UHASH_BITS(32)
UHASH_BITS(64)
UHASH_BITS(96)
UHASH_BITS(128)

#undef UHASH_BITS
