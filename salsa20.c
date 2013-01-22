#include <stdlib.h>
#include <string.h>
#include "util.h"

#include "salsa20.h"

#undef LITTLE_ENDIAN
#define LITTLE_ENDIAN

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
salsa20_init_key(salsa20_state *state, salsa20_variant variant,
		 const uint8_t *key, salsa20_key_size key_size)
{
  int i;
#ifdef LITTLE_ENDIAN
  const uint32_t *k32 = (uint32_t*)key;
#else
  const uint32_t k32[8];
  const size_t key_words = 4 + key_size * 4; /* 4 or 8 */
  for(i = 0; i < key_words; ++i)
    k32[i] = pack_littleendian(&key[i*4]);
#endif

  state->variant = variant;
  uint32_t *s = state->hash_input.bit32;

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
salsa20_init_iv(salsa20_state *iv_state, const salsa20_state *master,
		const uint8_t *iv)
{
  memcpy(iv_state, master, sizeof(salsa20_state));

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
      stream[i*4  ] = tmp;
      stream[i*4+1] = tmp >> 8;
      stream[i*4+2] = tmp >> 16;
      stream[i*4+3] = tmp >> 24;
    }
#endif
}

/*
int main()
{
  {
    uint32_t v[4] = {0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b};
    quarterround(v, v);
    int i;
    puts("quarterround:");
    for(i = 0; i < 4; ++i)
      printf(" 0x%08x", v[i]);
    putchar('\n');
  }

  {
    uint32_t v[16] =
      {0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
       0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
       0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
       0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a};
    rowround(v, v);
    int i;
    puts("rowround:");
    for(i = 0; i < 16; ++i) {
      printf(" 0x%08x", v[i]);
      if(i % 4 == 3)
	putchar('\n');
    }
    putchar('\n');
  }

  {
    uint32_t v[16] =
      {0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
       0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
       0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
       0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a};
    columnround(v, v);
    int i;
    puts("columnround:");
    for(i = 0; i < 16; ++i) {
      printf(" 0x%08x", v[i]);
      if(i % 4 == 3)
	putchar('\n');
    }
    putchar('\n');
  }

  {
    uint32_t v[16] =
      {0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
       0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
       0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
       0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1};
    doubleround(v, v);
    int i;
    puts("doubleround:");
    for(i = 0; i < 16; ++i) {
      printf(" 0x%08x", v[i]);
      if(i % 4 == 3)
	putchar('\n');
    }
    putchar('\n');
  }

  {
    uint8_t v1[64] =
      {6,124, 83,146, 38,191, 9, 50, 4,161, 47,222,122,182,223,185,
       75, 27, 0,216, 16,122, 7, 89,162,104,101,147,213, 21, 54, 95,
       225,253,139,176,105,132, 23,116, 76, 41,176,207,221, 34,157,108,
       94, 94, 99, 52, 90,117, 91,220,146,190,239,143,196,176,130,186};
    uint8_t v2[64];

    int i;
    for(i = 0; i < 500000; ++i)
      {
	salsa20_hash(10, (uint32_t*)v1, (uint32_t*)v2);
	salsa20_hash(10, (uint32_t*)v2, (uint32_t*)v1);
      }
 
    puts("salsa20_hash^100000:");
    for(i = 0; i < 64; ++i) {
      printf(",%3u", v1[i]);
      if(i % 16 == 15)
	putchar('\n');
    }
    putchar('\n');
  }
}
*/
