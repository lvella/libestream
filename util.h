/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#pragma once

#include <inttypes.h>
#include <stddef.h>

uint32_t rotl(uint32_t x, unsigned int n);

uint32_t pack_littleendian(const uint8_t *v);
void unpack_littleendian(uint32_t value, uint8_t *v);

size_t min(size_t a, size_t b);
