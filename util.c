uint32_t
rotl(uint32_t x, unsigned int n);
{
  return (x << n) | (x >> (32-n));
}
