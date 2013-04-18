#pragma once

#include <stddef.h>
#include <inttypes.h>
#include "buffered.h"

#if(__STDC_VERSION__ >= 199901L)
#define FLEX_ARRAY_MEMBER
#else
#define FLEX_ARRAY_MEMBER 1 // Non-standard usage, but widely accepted.
#endif

/* Internally used: */

typedef struct
{
  uint64_t v[2]; /* Big endian; 0: most significant; 1: least significant */
} uint128;

/* Key stuff: */

typedef struct
{
  uint64_t k64;
  uint128 k128;
} l2_key;

typedef struct
{
  uint16_t l2key_offset;
  uint16_t l3key1_offset;
  uint16_t l3key2_offset;
  uint8_t iters;
} uhash_key_attributes;

typedef struct
{
  const uhash_key_attributes *attribs;
} uhash_key;

/* State stuff */

typedef struct
{
  uint128 y;
  uint64_t tmp;
} l2_state;

typedef struct {
  uint64_t l1;
  l2_state l2;
} uhash_iteration_state;

typedef struct {
  uint8_t iters;
  uint8_t buffer_len;
  /** Data is copied to buffer in native byte order. */
  uint32_t buffer[8];
  /** How many 32 bytes steps performed so far. */
  uint64_t step_count;
} uhash_state_common;

typedef struct {
  uhash_state_common common;
  uhash_iteration_state partial[FLEX_ARRAY_MEMBER];
} uhash_state;

/** UHASH variations. */
typedef enum {
  UHASH_32 = 1,
  UHASH_64 = 2,
  UHASH_96 = 3,
  UHASH_128 = 4
} uhash_size;

/* Public interface: */

void uhash_key_setup(uhash_size type, uhash_key *key, buffered_state *full_state);

void uhash_init(const uhash_key *key, uhash_state *state);

void uhash_update(const uhash_key *key, uhash_state *state, const uint8_t *input, size_t len);

void uhash_finish(const uhash_key *key, uhash_state *state, uint8_t *output);

#define UHASH_BITS(bits)						\
  typedef struct							\
  {									\
    uhash_key header;							\
    uint32_t l1key[256 + (((bits)-1)/32) * 4];				\
    l2_key l2key[(bits)/32];						\
    uint64_t l3key1[(bits)/4];						\
    uint32_t l3key2[(bits)/32];						\
  } uhash_##bits##_key;							\
									\
  typedef struct							\
  {									\
    uhash_state_common common;						\
    uhash_iteration_state partial[(bits)/32];				\
  } uhash_##bits##_state;						\
									\
  void uhash_##bits##_key_setup(buffered_state *full_state,		\
				uhash_##bits##_key *key);		\
  									\
  void uhash_##bits##_init(uhash_##bits##_state *state);

UHASH_BITS(32)
UHASH_BITS(64)
UHASH_BITS(96)
UHASH_BITS(128)

#undef UHASH_BITS
