#include "util.h"

uint32_t
rotl(uint32_t x, unsigned int n)
{
  return (x << n) | (x >> (32-n));
}

uint32_t
pack_littleendian(const uint8_t *v)
{
  return (uint32_t)v[3] << 24
      | (uint32_t)v[2] << 16
      | (uint32_t)v[1] << 8
      | (uint32_t)v[0];
}
