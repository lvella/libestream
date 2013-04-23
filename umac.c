/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <endian.h>
#include "util.h"
#include "buffered.h"

#include "umac.h"

static void
unpack_bigendian(uint32_t value, uint8_t *out)
{
  /* Doesn't have big endian specific code because doesn't require output
     to be 4 byte aligned. */
  out[0] = value >> 24;
  out[1] = value >> 16;
  out[2] = value >> 8;
  out[3] = value;
}

/**
 * @param msg When cast from a byte array, must be in native byte-order...
 */
static uint64_t
nh_iteration(const uint32_t* key, const uint32_t* msg)
{
  uint64_t y = 0;
  int j;
  for(j = 0; j < 4; ++j)
    y += (uint64_t)(htole32(msg[j]) + key[j])
      * (uint64_t)(htole32(msg[4 + j]) + key[4 + j]);

  return y;
}

static void
mul64(uint64_t a, uint64_t b, uint128 *out)
{
  static const uint64_t b32_mask = ((uint64_t)1u << 32) - 1;
  uint64_t x0, x1, y0, y1;
  uint64_t tmp0, tmp1;

  x0 = a & b32_mask;
  x1 = a >> 32;
  y0 = b & b32_mask;
  y1 = b >> 32;

  /* Final multiplication: out.v[0] * 2^64 + (tmp0 + tmp1) * 2^32 + out.v[1]. */
  out->v[1] = x0 * y0;
  out->v[0] = x1 * y1;
  tmp0 = x1 * y0;
  tmp1 = x0 * y1;

  /* Sum tmp0 and tmp1 into a single 64 bits number (may carry). */
  tmp0 += tmp1;

  /* Add up least significant 32 bit part (may carry). */
  uint64_t least = tmp0 << 32;
  out->v[1] += least;

  /* Add up most significant 32 bit part and possible carries.
     This will not overflow, because the result final result can't be
     bigger than 128 bits. */
  out->v[0] += (tmp0 >> 32)
    + (tmp0 < tmp1 ? ((uint64_t)1u << 32) : 0) /* tmp0 + tmp1 carry */
    + (out->v[1] < least); /* out.v[1] + least carry */
}

static const uint64_t offset_p64 = 59;
static const uint64_t p64 = (uint64_t)0u - 59;

static uint64_t
sum_mod_p64(uint64_t x, uint64_t y)
{
  uint64_t lower = x + y;
  if(lower < x)
    return (lower - p64) % p64;
  else
    return lower % p64;
}

static uint64_t
mul_mod_p64(uint64_t x, uint64_t y)
{
  uint128 mul;
  mul64(x, y, &mul);

  uint64_t ret;

  /* Mod p64 of the most significative nibble, (may recurse).
     Can't prove right now, but if offset_p64 is small enough,
     recursion will stop very fast.*/
  if(mul.v[0] > 312656679215416129)
    /* If greater than the biggest number that multiplied by offset_p64
     * still fits in 64 bits, recurse. */
    ret = mul_mod_p64(mul.v[0], offset_p64);
  else
    ret = mul.v[0] * offset_p64;

  ret = sum_mod_p64(ret, mul.v[1]);

  return ret;
}

static uint64_t
poly64_iteration(uint64_t key, uint64_t m, uint64_t y)
{
  const uint64_t marker = p64 - 1;
  const uint64_t maxwordrange = 0xffffffff00000000u;

  y = mul_mod_p64(key, y);
  if(m >= maxwordrange)
    {
      y = sum_mod_p64(y, marker);
      y = sum_mod_p64(mul_mod_p64(key, y), m - offset_p64);
    }
  else
    y = sum_mod_p64(y, m);

  return y;
}

typedef struct {
  uint128 most;
  uint128 least;
} uint256;

static void
mul128(const uint128 *a, const uint128 *b, uint256 *out)
{
  static const uint64_t b32_mask = ((uint64_t)1u << 32) - 1;

  uint128 tmp0, tmp1;

  /* Final multiplication: most * 2^128 + (tmp0 + tmp1) * 2^64 + least. */
  mul64(a->v[1], b->v[1], &out->least);
  mul64(a->v[0], b->v[0], &out->most);
  mul64(a->v[0], b->v[1], &tmp0);
  mul64(a->v[1], b->v[0], &tmp1);

  int carry;

  /* Sum tmp0 and tmp1 into a single 128 bits number. */
  tmp0.v[1] += tmp1.v[1];
  carry = tmp0.v[1] < tmp1.v[1];

  tmp0.v[0] += tmp1.v[0];
  if(tmp0.v[0] < tmp1.v[0] || (carry && tmp0.v[0] == UINT64_MAX))
    /* If overflow, add carry to most significant word. */
    ++out->most.v[0];

  tmp0.v[0] += carry;

  /* Add up least significant 64 bit part of tmp (may carry). */
  out->least.v[0] += tmp0.v[1];
  carry = out->least.v[0] < tmp0.v[1];

  /* Add up most significant 64 bit part of tmp and the carrie. */
  out->most.v[1] += tmp0.v[0];
  if(out->most.v[1] < tmp0.v[0] || (carry && out->most.v[1] == UINT64_MAX))
    /* If overflow, add carry to most significant word. */
    ++out->most.v[0];

  out->most.v[1] += carry;
}

static const uint64_t offset_p128 = 159;
static const uint128 marker_p128 = {{0xFFFFFFFFFFFFFFFF,
				     0xFFFFFFFFFFFFFF60}};
static const uint128 p128 = {{0xFFFFFFFFFFFFFFFF,
			      0xFFFFFFFFFFFFFF61}};

/**
 * @param x must be different from out.
 * @param y may be the same as out.
 * @param out may be the same as y.
 */
static void
sum_mod_p128(const uint128 *x, const uint128 *y, uint128 *out)
{
  /* First, easily compute least significant bits of sum. */
  out->v[1] = y->v[1] + x->v[1];
  register int carry = out->v[1] < x->v[1];

  /* Now the complicated most significant bits: */

  /* Add carry with first term nibble. */
  out->v[0] = carry + y->v[0];
  carry = out->v[0] < carry; /* Get carry of this operation. */

  /* Add result with second term nibble. */
  out->v[0] += x->v[0];
  carry |= out->v[0] < x->v[0]; /* Get new carry or keep old carry. */

  /* If overflow (has carry), take modulus. */
  if(carry)
    {
      out->v[1] += offset_p128;
      if(out->v[1] < offset_p128 && !++out->v[0])
          out->v[1] += offset_p128;
    }
  /* Otherwise, take modulus if needed. */
  else if(out->v[0] == p128.v[0] && out->v[1] >= p128.v[1])
    {
      out->v[0] = 0;
      out->v[1] -= p128.v[1];
    }
}

/**
 * @param x may be the same as out.
 * @param y may be the same as out.
 * @param out may be the same as x and/or y.
 */
static void
mul_mod_p128(const uint128 *x, const uint128 *y, uint128 *out)
{
  const uint128 offset = {{0, offset_p128}};
  uint256 mul;
  mul128(x, y, &mul);

  uint256 inter; /* Only inter.least is actually used. */

  /* Mod p128 of the most significative nibble, (may recurse).
     Can't prove right now, but if offset_p64 is small enough,
     recursion will stop very fast.*/
  if(mul.most.v[0] < 0x19c2d14ee4a1019u
     || (mul.most.v[0] == 0x19c2d14ee4a1019u
	 && mul.most.v[1] <= 0xc2d14ee4a1019c2du))
    /* If multiplication will fit, do simple multiplication. */
    /* TODO: could implement mul(u128, u64) -> u128, since we
       know result will be at most 128 bits. */
    mul128(&mul.most, &offset, &inter);
  else {
    /* Otherwise, recurse. */
    mul_mod_p128(&mul.most, &offset, &inter.least);
  }

  sum_mod_p128(&inter.least, &mul.least, out);
}

static void
poly128_iteration(const uint128 *key, const uint128 *m, uint128 *y)
{
  const uint64_t maxwordrange_msw = 0xffffffff00000000u;

  mul_mod_p128(key, y, y);
  if(m->v[0] >= maxwordrange_msw)
    {
      sum_mod_p128(&marker_p128, y, y);
      mul_mod_p128(key, y, y);

      /* Calculate dif = (m - offset) */
      uint128 dif = {{m->v[0],
		      m->v[1] - offset_p128}};
      if(dif.v[1] > m->v[1])
	--dif.v[0];

      sum_mod_p128(&dif, y, y);
    }
  else
    sum_mod_p128(m, y, y);
}

static const uint32_t l2_limit = (1u << 19);

static void
l2_hash_iteration(const l2_key *key, l2_state *state,
		  uint64_t input, size_t step_count)
{
  if(step_count <= l2_limit)
    state->y.v[1] = poly64_iteration(key->k64, input, state->y.v[1]);
  else if((step_count % 64) && (step_count % 64) <= 32)
    {
      if(step_count <= (l2_limit + 32))
	{
	  /* First chunk after initial 16 MB, must kickstart POLY-128. */
	  uint128 m = {0, state->y.v[1]};
	  state->y.v[1] = 1;
	  poly128_iteration(&key->k128, &m, &state->y);
	}

      state->tmp = input;
    }
  else
    {
      uint128 m = {state->tmp, input};
      poly128_iteration(&key->k128, &m, &state->y);
    }
}

static void
l2_hash_finish_big(const l2_key *key, l2_state *state, size_t step_count)
{
  uint128 m;

  if((step_count % 64) && (step_count % 64 <= 32))
    {
      m.v[0] = state->tmp;
      m.v[1] = 0x8000000000000000u;
    }
  else
    {
      m.v[0] = 0x8000000000000000u;
      m.v[1] = 0;
    }

  poly128_iteration(&key->k128, &m, &state->y);
}

static const uint64_t p36 = 0x0000000FFFFFFFFBu;
static uint32_t
l3_hash(const uint64_t *k1, uint32_t k2, const uint128 *m)
{
  uint64_t y = 0;
  int i, k;

  /* Skip first iteration if uneeded; the result would be zero anyway.
     It happens too often, when message is smaller than 16MB. */
  for(k = (m->v[0] == 0); k < 2; ++k) {
    for(i = 0; i < 4; ++i)
      /*Althoug always increasing, y never warps around because operands
	are too small. */
      y = y
	+ k1[k * 4 + i] /* Key (mod p36 done in key initialization). */
	* ((m->v[k] >> (16 * (3 - i))) /* Shift relevant 16 bit to place. */
	   & 0xffffu); /* Filter selected 16 lower bits. */
  }

  return (uint32_t)(y % p36) ^ k2;
}

static inline void
uhash_step(const uint32_t *buffer, uint64_t step_count,
    const uint32_t *l1key, const l2_key *l2key,
    uhash_iteration_state *partial)
{
  int substep = step_count % 32;
  if(step_count && substep == 0) {
    l2_hash_iteration(l2key, &partial->l2, partial->l1 + 8192u, step_count);
    partial->l1 = 0;
  }

  partial->l1 += nh_iteration(l1key + substep * 8, buffer);
}

static inline void
uhash_step_iterations(const uhash_key *key, uhash_state *state, const uint32_t *buffer)
{
  const uint8_t *key_base = (const uint8_t *)key;
  int i;
  for(i = 0; i < state->common.iters; ++i) {
    uhash_step(buffer, state->common.step_count,
	(const uint32_t *)(key_base + sizeof(uhash_key) + (i * 16)),
	(const l2_key *)(key_base + key->attribs->l2key_offset + (i * 24)),
        &state->partial[i]);
  }
  ++state->common.step_count;
}

#define UHASH_SPECIFICS_DEF(bits)					\
  const uhash_key_attributes uhash_##bits##_attributes = {		\
    .l2key_offset = offsetof(uhash_##bits##_key, l2key),		\
    .l3key1_offset = offsetof(uhash_##bits##_key, l3key1),		\
    .l3key2_offset = offsetof(uhash_##bits##_key, l3key2),		\
    .iters = ((bits)/32)						\
  };

UHASH_SPECIFICS_DEF(32)
UHASH_SPECIFICS_DEF(64)
UHASH_SPECIFICS_DEF(96)
UHASH_SPECIFICS_DEF(128)

#undef UHASH_SPECIFICS_DEF

const uhash_key_attributes *const uhash_attributes_array[4] = {
    &uhash_32_attributes,
    &uhash_64_attributes,
    &uhash_96_attributes,
    &uhash_128_attributes
};

void
uhash_key_setup(uhash_type type, uhash_key *key, buffered_state *full_state)
{
  int iters = (size_t)type + 1;
  uint8_t *key_base = (uint8_t *)key;
  const uhash_key_attributes *attribs;

  key->attribs = attribs = uhash_attributes_array[iters];

  /* Extract L1 key. */
  buffered_action(full_state, key_base + sizeof(uhash_key), 1024 + (iters - 1) * 16, BUFFERED_EXTRACT);

  /* Extract and process L2 key. */
  {
    int i;

    /** Room for biggest possible L2 key. */
    uint64_t l2_keydata[12];

    buffered_action(full_state, (uint8_t*)l2_keydata, iters * 24, BUFFERED_EXTRACT);

    for(i = 0; i < iters; ++i)
    {
      static const uint64_t keymask = 0x01ffffff01ffffffu;
      l2_key *l2key = (l2_key *)(key_base + attribs->l2key_offset) + i;

      l2key->k64 = l2_keydata[i*3] & keymask;
      l2key->k128.v[1] = l2_keydata[i*3 + 1] & keymask;
      l2key->k128.v[0] = l2_keydata[i*3 + 2] & keymask;
    }
  }

  /* Extract and process L3 keys. */
  {
    int i;
    uint64_t *l3key1 = (uint64_t *)(key_base + attribs->l3key1_offset);

    buffered_action(full_state, (uint8_t*)l3key1, iters * 64, BUFFERED_EXTRACT);
    for(i = 0; i < iters * 8; ++i)
      l3key1[i] %= p36;

    buffered_action(full_state, key_base + attribs->l3key2_offset, iters * 4, BUFFERED_EXTRACT);
  }
}

void
uhash_init(uhash_type type, uhash_state *state)
{
  int i;
  int iters;

  state->common.iters = iters = (size_t)type + 1;
  state->common.buffer_len = 0;
  state->common.step_count = 0;

  for(i = 0; i < iters; ++i) {
    state->partial[i].l1 = 0;
    state->partial[i].l2.y.v[0] = 0;
    state->partial[i].l2.y.v[1] = 1;
  }
}

void
uhash_update(const uhash_key *key, uhash_state *state, const uint8_t *input, size_t len)
{
  size_t processed = 0;

  /* If buffer is partially filled, try to complete it. */
  if(state->common.buffer_len) {
    size_t to_copy;
    assert(state->common.buffer_len < 32);
    to_copy = min(32 - state->common.buffer_len, len);

    memcpy((uint8_t*)state->common.buffer + state->common.buffer_len, input, to_copy);
    state->common.buffer_len += to_copy;
    processed += to_copy;

    /* If full, process it. */
    if(state->common.buffer_len == 32) {
      uhash_step_iterations(key, state, state->common.buffer);
      state->common.buffer_len = 0;
    }
  }

  /* For the rest of the input, process in 32 bytes chunks. */
  if(UNALIGNED_ACCESS_ALLOWED || ((uintptr_t)(input + processed) & 3u) == 0) {
    /* If the machine supports unaligned memory access, or the memory happens to be aligned,
     * use the input pointer directly. */
    for(; processed + 32 <= len; processed += 32)
      uhash_step_iterations(key, state, (const uint32_t *)(input + processed));
  } else {
    /* Memory must be aligned before casting to 32bits, so copy it to the aligned buffer
     * before using. */
    for(; processed + 32 <= len; processed += 32) {
      memcpy(state->common.buffer, input + processed, 32);
      uhash_step_iterations(key, state, state->common.buffer);
    }
  }

  /* Finally, copy the leftover into buffer for future processing. */
  state->common.buffer_len = len - processed;
  memcpy(state->common.buffer, input + processed, state->common.buffer_len);
}

void uhash_finish(const uhash_key *key, uhash_state *state, uint8_t *output)
{
  /* TODO: move all "for iters" to outer loop. It doesn't pay to have them inner. */
  const uint8_t *key_base = (const uint8_t *)key;
  uint64_t to_add_l1;
  int has_leftover, must_run_l2;
  int substep = state->common.step_count % 32;
  int i;

  /* Number of bits input to the last L1 iteration. */
  to_add_l1 = substep * 32 + state->common.buffer_len;
  if(!to_add_l1 && state->common.step_count)
    to_add_l1 = 8192u;
  else
    to_add_l1 *= 8;

  /* If there is something in the buffer, or input was empty,
   * pad-fill with zeroes... */
  has_leftover = state->common.buffer_len || !state->common.step_count;
  if(has_leftover) {
    memset((uint8_t *)state->common.buffer + state->common.buffer_len,
	0, 32 - state->common.buffer_len);
  }

  must_run_l2 = (state->common.step_count > 32 && substep == 0)
		    || (state->common.step_count == 32 && state->common.buffer_len);

  /* For each algorithm iteration... */
  for(i = 0; i < state->common.iters; ++i) {
    uhash_iteration_state *partial = &state->partial[i];
    size_t step_count = state->common.step_count;
    const l2_key *l2key = (const l2_key *)(key_base + key->attribs->l2key_offset + (i * 24));

    /* If there is a full L1 completed, and more than 1024 bytes, then L2 hash it. */
    if(must_run_l2) {
      l2_hash_iteration(l2key, &partial->l2, partial->l1 + 8192u, step_count);
      partial->l1 = 0;
    }

    /* Process the leftover on buffer. */
    if(has_leftover) {
      partial->l1 += nh_iteration((const uint32_t *)(key_base + sizeof(uhash_key)) + 4 * i + substep * 8,
	  (const uint32_t *)state->common.buffer);
      ++step_count;
    }

    /* Find the input for L3 hash, either L1 output, if string is small, or one
     * possible last iteration of L2. */
    if(step_count <= 32) {
      partial->l2.y.v[1] = partial->l1 + to_add_l1;
    } else {
      if(state->common.buffer_len || step_count % 32 != 0) {
	l2_hash_iteration(l2key, &partial->l2, partial->l1 + to_add_l1, step_count);
      }

      if(step_count > l2_limit) {
	l2_hash_finish_big(l2key, &partial->l2, step_count);
      }
    }

    /* Finally, run L3 hash and calculates output. */
    unpack_bigendian(
	l3_hash((const uint64_t *)(key_base + key->attribs->l3key1_offset + (i * 64)),
	    *(const uint32_t *)(key_base + key->attribs->l3key2_offset + (i * 4)),
	    &state->partial[i].l2.y),
	&output[i*4]);
  }
}

