/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdio.h>
#include "util.h"

#include "rabbit.h"

static void
print_state(rabbit_state *s)
{
  printf( "     b  = %d\n"
	  "     X0 = 0x%08X", s->carry, s->x[0]);
  uint32_t *v[2] = {s->x, s->c};
  char l[2] = {'X', 'C'};

  int i, j;
  for(i = 1; i < 16; ++i) {
    fputs((i % 4) ? ", " : ",\n     ", stdout);
    printf("%c%d = 0x%08X", l[i/8], i%8, v[i/8][i%8]);
  }
  puts("\n");
}

static uint32_t
g(uint32_t u, uint32_t v)
{
  uint64_t square = (uint64_t)(u+v) * (uint64_t)(u+v);
  return (square >> 32) ^ square;
}

static void
algorithm_round(rabbit_state *s)
{
  int i;
  uint32_t *x = s->x;
  uint32_t *c = s->c;

  static const uint32_t A[] =
    { 0x4D34D34Du, 0xD34D34D3u,
      0x34D34D34u, 0x4D34D34Du,
      0xD34D34D3u, 0x34D34D34u,
      0x4D34D34Du, 0xD34D34D3u };

  uint8_t b = s->carry;
  for(i = 0; i < 8; ++i)
    {
      /* This ended up being the "best" way to get the carry bit... */
      uint64_t tmp = (uint64_t)c[i] + A[i] + b;
      c[i] = tmp;
      b = tmp >> 32;
    }
  s->carry = b;

  uint32_t gv[8];

  for(i = 0; i < 8; ++i)
    gv[i] = g(x[i], c[i]);

  x[0] = gv[0] + rotl(gv[7], 16) + rotl(gv[6], 16);
  x[1] = gv[1] + rotl(gv[0], 8 ) + gv[7];
  x[2] = gv[2] + rotl(gv[1], 16) + rotl(gv[0], 16);
  x[3] = gv[3] + rotl(gv[2], 8 ) + gv[1];
  x[4] = gv[4] + rotl(gv[3], 16) + rotl(gv[2], 16);
  x[5] = gv[5] + rotl(gv[4], 8 ) + gv[3];
  x[6] = gv[6] + rotl(gv[5], 16) + rotl(gv[4], 16);
  x[7] = gv[7] + rotl(gv[6], 8 ) + gv[5];
}

static uint16_t
cat8(uint8_t a, uint8_t b)
{
  return ((uint16_t)a << 8) | b;
}

static uint32_t
cat16(uint16_t a, uint16_t b)
{
  return ((uint32_t)a << 16) | b;
}

void
rabbit_init_key(rabbit_state *s, const uint8_t *key)
{
  int i;

#ifdef LITTLE_ENDIAN
  uint16_t *k = (uint16_t*)key;
#else /* works everywhere */
  uint16_t k[8];

  for(i = 0; i < 8; ++i)
    k[i] = cat8(key[i*2+1], key[i*2]);
#endif

  s->carry = 0;

  register uint32_t *x = s->x;
  register uint32_t *c = s->c;
  for(i = 0; i < 8; ++i)
    if(i&1u) /* odd */
      {
	x[i] = cat16(k[(i+5) % 8], k[(i+4) % 8]);
	c[i] = cat16(k[i]        , k[(i+1) % 8]);
      }
    else /* even */
      {
	x[i] = cat16(k[(i+1) % 8], k[i]);
	c[i] = cat16(k[(i+4) % 8], k[(i+5) % 8]);
      }

  for(i = 0; i < 4; ++i)
    algorithm_round(s);

  for(i = 0; i < 8; ++i)
    c[i] ^= x[(i+4) % 8];
}

void rabbit_init_iv(rabbit_state *iv_state, const rabbit_state *master,
		    const uint8_t *iv)
{
  int i;

  *iv_state = *master;

  {
    uint32_t *c = iv_state->c;

#ifdef LITTLE_ENDIAN
    uint16_t *iv16 = (uint16_t*)iv;
    uint32_t *iv32 = (uint32_t*)iv;
#else /* works everywhere */
    uint16_t iv16[4];
    uint32_t iv32[2];

    for(i = 0; i < 4; ++i)
      iv16[i] = cat8(iv[i*2+1], iv[i*2]);
    for(i = 0; i < 2; ++i)
      iv32[i] = cat16(iv16[i*2+1], iv16[i*2]);
#endif

    uint32_t iv0101 = cat16(        iv16[2],      iv16[0]);
    uint32_t iv1010 = cat16(iv16[3],       iv16[1]       );

    c[0] ^= iv32[0];
    c[1] ^= iv1010;
    c[2] ^= iv32[1];
    c[3] ^= iv0101;
    c[4] ^= iv32[0];
    c[5] ^= iv1010;
    c[6] ^= iv32[1];
    c[7] ^= iv0101;
  }

  for(i = 0; i < 4; ++i)
    {
      algorithm_round(iv_state);
    }
}

void
rabbit_extract(rabbit_state *state, uint8_t *stream)
{
  algorithm_round(state);

  uint16_t *s = (uint16_t*)stream;
  uint32_t *x = state->x;

  s[0] = (uint16_t) x[0]        ^ (uint16_t)(x[5] >> 16);
  s[1] = (uint16_t)(x[0] >> 16) ^ (uint16_t) x[3];
  s[2] = (uint16_t) x[2]        ^ (uint16_t)(x[7] >> 16);
  s[3] = (uint16_t)(x[2] >> 16) ^ (uint16_t) x[5];
  s[4] = (uint16_t) x[4]        ^ (uint16_t)(x[1] >> 16);
  s[5] = (uint16_t)(x[4] >> 16) ^ (uint16_t) x[7];
  s[6] = (uint16_t) x[6]        ^ (uint16_t)(x[3] >> 16);
  s[7] = (uint16_t)(x[6] >> 16) ^ (uint16_t) x[1];

#ifndef LITTLE_ENDIAN
  /* works everywhere, but changes nothing in little endian */
  int i;
  for(i = 0; i < 8; ++i) {
    uint16_t tmp = s[i];
    stream[i*2] = tmp;
    stream[i*2 + 1] = tmp >> 8;
  }
#endif
}
