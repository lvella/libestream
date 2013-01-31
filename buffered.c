#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "buffered.h"

#define CIPHER_SPECIFICS_DEF(name,size)					\
  const cipher_attributes name##_cipher = {				\
    .extract_func = (extract_func_type)name##_extract,			\
    .buffered_state_size = sizeof(name##_state_buffered),		\
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

static uint8_t *
memxor(uint8_t *dest, const uint8_t *mask, size_t n)
{
  size_t i;
  if(is_aligned(dest))
    {
      uint64_t *d64 = (uint64_t*)dest;
      uint64_t *m64 = (uint64_t*)mask;
      size_t wlen = n / 8;
      for(i = 0; i < wlen; ++i)
	d64[i] ^= m64[i];
      dest += wlen * 8;
      mask += wlen * 8;
      n %= 8;
    }

  for(i = 0; i < n; ++i)
    dest[i] ^= mask[i];

  return NULL;
}

void
buffered_action(const cipher_attributes *cipher, void *buffered_state,
		uint8_t *stream, size_t len, buffered_ops op)
{
  typedef void *(*memop_func)(void *dest, const void *src, size_t n);
  memop_func memops[] =
    {
      memcpy,
      (memop_func)memxor
    };

  const uint8_t chunk_size = cipher->chunk_size;
  uint8_t count = ((uint8_t*)buffered_state)[cipher->count_offset];
  uint8_t *cbuffer = (uint8_t*)buffered_state + cipher->buffer_offset;

  assert(is_aligned(cbuffer) && "Unaligned buffered_state");

  /* First, use up whatever is in the buffer */
  if(count > 0)
    {
      size_t to_copy = min(count, len);
      memops[op](stream, cbuffer + chunk_size - count , to_copy);
      count -= to_copy;
      len -= to_copy;
      stream += to_copy;
    }

  /* Then extract while len is multiple of the chunk_size */
  int i = len / chunk_size;
  uint8_t remainder = len % chunk_size;
  /* If aligned correctly, can spare one extra copy. */
  if(op == BUFFERED_EXTRACT && is_aligned(stream))
    for(; i > 0; --i)
      {
	cipher->extract_func(buffered_state, stream);
	stream += chunk_size;
      }
  else
    for(; i > 0; --i)
      {
	cipher->extract_func(buffered_state, cbuffer);
	memops[op](stream, cbuffer, chunk_size);
	stream += chunk_size;
      }

  /* Finally, extract the next chunk to state buffer, and fill up the
   * remaining non-multiple bytes. */
  if(remainder)
    {
      cipher->extract_func(buffered_state, cbuffer);
      memops[op](stream, cbuffer, remainder);
      count = chunk_size - remainder;
    }

  ((uint8_t*)buffered_state)[cipher->count_offset] = count;
}

void buffered_skip(const cipher_attributes *cipher, void *buffered_state,
		   size_t len)
{
  const uint8_t chunk_size = cipher->chunk_size;
  uint8_t count = ((uint8_t*)buffered_state)[cipher->count_offset];
  uint8_t *cbuffer = (uint8_t*)buffered_state + cipher->buffer_offset;

  if(len <= count)
      count -= len;
  else
    {
      len -= count;
      count = 0;
      
      int i;
      uint8_t remainder = len % chunk_size;
      for(i = len / chunk_size; i > 0; --i)
	cipher->extract_func(buffered_state, cbuffer);

      if(remainder)
	{
	  cipher->extract_func(buffered_state, cbuffer);
	  count = chunk_size - remainder;
	}
    }
  ((uint8_t*)buffered_state)[cipher->count_offset] = count;
}
