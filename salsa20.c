/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdlib.h>
#include <string.h>
#include "util.h"

#include "salsa20.h"

#undef LITTLE_ENDIAN
//#define LITTLE_ENDIAN

#ifdef LITTLE_ENDIAN
#warning "Little endian code."
#endif

/**
 * @param in may be the same as out
 */
static void
quarterround(const uint32_t *in, uint32_t *out)
{
  out[1] = in[1] ^ rotl(in[0] + in[3], 7);
  out[2] = in[2] ^ rotl(out[1] + in[0], 9);
  out[3] = in[3] ^ rotl(out[2] + out[1], 13);
  out[0] = in[0] ^ rotl(out[3] + out[2], 18);
}

static void
permut_do(const uint32_t *in, uint32_t *out, const uint8_t *in_idx, size_t len)
{
  size_t i;
  for(i = 0; i < len; ++i)
    out[i] = in[in_idx[i]];
}

static void
permut_undo(const uint32_t *in, uint32_t *out, const uint8_t *out_idx, size_t len)
{
  size_t i;
  for(i = 0; i < len; ++i)
    out[out_idx[i]] = in[i];
}

static void
rowround(const uint32_t *in, uint32_t *out)
{
  quarterround(in, out);

  const uint8_t permut[3][4] =
    {{5, 6, 7, 4},
     {10, 11, 8, 9},
     {15, 12, 13, 14}};

  int i;
  for(i = 0; i < 3; ++i)
    {
      uint32_t tmp[4];
      permut_do(in, tmp, permut[i], 4);
      quarterround(tmp, tmp);
      permut_undo(tmp, out, permut[i], 4);
    }
}

static void
columnround(const uint32_t *in, uint32_t *out)
{
  const uint8_t permut[4][4] =
    {{0, 4, 8, 12},
     {5, 9, 13, 1},
     {10, 14, 2, 6},
     {15, 3, 7, 11}};

  int i;
  for(i = 0; i < 4; ++i)
    {
      uint32_t tmp[4];
      permut_do(in, tmp, permut[i], 4);
      quarterround(tmp, tmp);
      permut_undo(tmp, out, permut[i], 4);
    }
}

static void
doubleround(const uint32_t *in, uint32_t *out)
{
  columnround(in, out);
  rowround(out, out);
}

/**
 * @param in must be different from out
 * @param drounds half the round count
 */
static void
salsa20_hash(char drounds, const uint32_t *in, uint32_t *out)
{
  int i, j;

  doubleround(in, out);
  for(i = 1; i < drounds; ++i)
    doubleround(out, out);

  for(i = 0; i < 16; ++i)
    out[i] += in[i];
}

void
salsa20_init_key(salsa20_master_state *state, salsa20_variant variant,
		 const uint8_t *key, salsa20_key_size key_size)
{
  int i;
#ifdef LITTLE_ENDIAN
  const uint32_t *k32 = (uint32_t*)key;
#else
  uint32_t k32[8];
  const size_t key_words = 4 + key_size * 4; /* 4 or 8 */
  for(i = 0; i < key_words; ++i)
    k32[i] = pack_littleendian(&key[i*4]);
#endif

  state->incomplete_state.variant = variant;
  uint32_t *s = state->incomplete_state.hash_input.bit32;

  static const uint32_t consts[2][4] = 
    {{0x3120646e, 0x79622d36}, /* Tau, 128-bits */
     {0x3320646e, 0x79622d32}}; /* Sigma, 256-bits */

  s[0] = 0x61707865;
  memcpy(s+1, k32, 16);
  s[5] = consts[key_size][0];
  // s[6..9] will be set at IV setup
  s[10] = consts[key_size][1];
  memcpy(s+11, &k32[key_size * 4], 16);
  s[15] = 0x6b206574;
}

void
salsa20_init_iv(salsa20_state *iv_state, const salsa20_master_state *master,
		const uint8_t *iv)
{
  memcpy(iv_state, &master->incomplete_state, sizeof(salsa20_state));

#ifdef LITTLE_ENDIAN
  iv_state->hash_input.bit64[3] = *(uint64_t*)iv;
#else
  iv_state->hash_input.bit32[6] = pack_littleendian(iv    );
  iv_state->hash_input.bit32[7] = pack_littleendian(iv + 4);
#endif

  iv_state->hash_input.bit64[4] = 0; /* Counter initalization. */
}

void
salsa20_set_counter(salsa20_state *state, uint64_t counter)
{
#ifdef LITTLE_ENDIAN
  state->hash_input.bit64[4] = counter;
#else
  state->hash_input.bit32[8] = counter;
  state->hash_input.bit32[9] = counter >> 32;
#endif
}

void
salsa20_extract(salsa20_state *state, uint8_t *stream)
{
  salsa20_hash(state->variant, state->hash_input.bit32, (uint32_t*)stream);

#ifdef LITTLE_ENDIAN
  ++state->hash_input.bit64[4];
#else
  /* I am trusting the branch preditor here... */
  if(!++state->hash_input.bit32[8])
    ++state->hash_input.bit32[9];

  int i;
  for(i = 0; i < 16; ++i)
    {
      uint32_t tmp = ((uint32_t*)stream)[i];
      unpack_littleendian(tmp, &stream[i*4]);
    }
#endif
}
