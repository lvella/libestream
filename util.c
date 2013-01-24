#include "util.h"

uint32_t
rotl(uint32_t x, unsigned int n)
{
  return (x << n) | (x >> (32-n));
}

uint32_t
pack_littleendian(const uint8_t *v)
{
#ifdef LITTLE_ENDIAN
  return *((uint32_t*)v);
#else
  return (uint32_t)v[3] << 24
      | (uint32_t)v[2] << 16
      | (uint32_t)v[1] << 8
      | (uint32_t)v[0];
#endif
}

uint32_t
unpack_littleendian(uint32_t value, uint8_t *v)
{
#ifdef LITTLE_ENDIAN
  *((uint32_t*)v) = value;
#else
  int i;
  for(i = 0; i < 4; ++i)
    v[i] = value >> (i * 8);
#endif
}
