#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "hc-128.h"
#include "rabbit.h"
#include "salsa20.h"
#include "sosemanuk.h"

#include "buffered.h"

#define CIPHER_SPECIFICS_DEF(name,size)					\
  const cipher_attributes name##_cipher = {				\
    .extract_func = (extract_func_type)name##_extract,			\
    .count_offset = offsetof(name##_state_buffered, available_count),	\
    .buffer_offset = offsetof(name##_state_buffered, buffer),		\
    .chunk_size = size							\
  };

CIPHER_SPECIFICS_DEF(hc128, 4)
CIPHER_SPECIFICS_DEF(rabbit, 16)
CIPHER_SPECIFICS_DEF(salsa20, 64)
CIPHER_SPECIFICS_DEF(sosemanuk, 16)

#undef CIPHER_SPECIFICS_DEF

static int
is_aligned(void *ptr)
{
  return ((unsigned long)ptr & 3u) == 0; /* Multiple of 4 */
}

void
buffered_extract(const cipher_attributes *cipher, void *buffered_state,
		 uint8_t *buffer, size_t len)
{
  const uint8_t chunk_size = cipher->chunk_size;
  uint8_t count = ((uint8_t*)buffered_state)[cipher->count_offset];
  uint8_t *cbuffer = (uint8_t*)buffered_state + cipher->buffer_offset;

  assert(is_aligned(cbuffer) && "Unaligned buffered_state");

  /* First, use up whatever is in the buffer */
  if(count > 0)
    {
      size_t to_copy = (count < len) ? count : len;
      memcpy(buffer, cbuffer + chunk_size - count , to_copy);
      count -= to_copy;
      len -= to_copy;
      buffer += to_copy;
    }

  /* Then extract while len is multiple of the chunk_size */
  size_t i = len / chunk_size;
  uint8_t remainder = len % chunk_size;
  /* If aligned correctly, can spare one extra copy. */
  if(is_aligned(buffer))
    {
      for(; i >= 0; --i)
      {
	cipher->extract_func(buffered_state, cbuffer);
	memcpy(buffer, cbuffer, chunk_size);
	buffer += chunk_size;
      }
    }
  else
    for(; i >= 0; --i)
      {
	cipher->extract_func(buffered_state, buffer);
	buffer += chunk_size;
      }

  /* Finally, extract the next chunk to state buffer, and fill up the
   * remaining non-multiple bytes. */
  if(remainder)
    {
      cipher->extract_func(buffered_state, cbuffer);
      memcpy(buffer, cbuffer, remainder);
      count = chunk_size - remainder;
    }

  ((uint8_t*)buffered_state)[cipher->count_offset] = count;
}
