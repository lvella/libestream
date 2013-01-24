#pragma once

#include <inttypes.h>

typedef struct
{
  uint32_t p[512];
  uint32_t q[512];
  uint16_t i;
} hc128_state;

void hc128_init(hc128_state *state, const uint8_t *key, const uint8_t *iv);

void hc128_extract(hc128_state *state, uint8_t *stream);
