#include "hc-128.h"

static const unsigned int mask = 0x1ff; /* 511 mask, for mod 512 */

static uint32_t
f1(uint32_t x)
{
  return rotl(x, 25) ^ rotl(x, 14) ^ (x >> 3);
}

static uint32_t
f2(uint32_t x)
{
  return rotl(x, 15) ^ rotl(x, 13) ^ (x >> 10);
}

static uint32_t
g1(uint32_t x, uint32_t y, uint32_t z)
{
  return (rotl(x, 22) ^ rotl(z, 9)) + rotl(y, 24);
}

static uint32_t
g2(uint32_t x, uint32_t y, uint32_t z)
{
  return (rotl(x, 10) ^ rotl(z, 23)) + rotl(y, 8);
}

static uint32_t
h(const uint32_t *qp, uint32_t x)
{
  return qp[x & 0xFFu] + qp[256 + ((x >> 16) & 0xFFu)];
}

static uint32_t
round_expression(uint32_t *pq, const uint32_t *qp,
		 uint32_t (*g)(uint32_t x, uint32_t y, uint32_t z),
		 uint16_t i)
{
  pq[i] += g(pq[(i-3u) & mask], pq[(i-10u) & mask], pq[(i+1u) & mask]);
  return pq[i] ^ h(qp, pq[(i-12u) & mask]);
}

void
hc128_init(hc128_state *state, const uint8_t *key, const uint8_t *iv)
{
  unsigned int i;
  uint32_t w[1280];

  for(i = 0; i < 4; ++i) {
    w[i] = w[i+4] = pack_littleendian(key + 4 * i);
    w[i+8] = w[i+12] = pack_littleendian(iv + 4 * i);
  }

  for(i = 16; i < 1280; ++i) {
    w[i] = f2(w[i-2]) + w[i-7] + f1(w[i-15]) + w[i-16] + i;
  }

  uint32_t *p = state->p;
  uint32_t *q = state->q;

  for(i = 0; i < 512; ++i)
    {
      p[i] = w[i+256];
      q[i] = w[i+768];
    }

  for(i = 0; i < 512; ++i)
    p[i] = round_expression(p, q, g1, i);

  for(i = 0; i < 512; ++i)
    q[i] = round_expression(q, p, g2, i);

  state->i = 0;
}

uint32_t
hc128_extract(hc128_state *state)
{
  uint16_t i = state->i;

  state->i = (i+1u) & 1023u;

  return (i < 512)
    ? round_expression(state->p, state->q, g1, i       )
    : round_expression(state->q, state->p, g2, i & mask);
}
