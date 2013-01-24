#pragma once

#include <inttypes.h>

uint32_t rotl(uint32_t x, unsigned int n);
uint32_t pack_littleendian(const uint8_t *v);
uint32_t unpack_littleendian(uint32_t value, uint8_t *v);
