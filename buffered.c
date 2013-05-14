#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "util.h"

#include "buffered.h"

#define CIPHER_SPECIFICS_DEF(name,size)					\
  const cipher_attributes name##_cipher = {				\
    .extract_func = (extract_func_type)name##_extract,			\
    .buffered_state_size = sizeof(name##_buffered_state),		\
    .buffer_offset = offsetof(name##_buffered_state, buffer),		\
    .chunk_size = size							\
  };									\
  const name##_buffered_state name##_static_initializer = {		\
      .header = { .cipher = &name##_cipher, .available_count = 0 }	\
  };

CIPHER_SPECIFICS_DEF(hc128, 4)
CIPHER_SPECIFICS_DEF(rabbit, 16)
CIPHER_SPECIFICS_DEF(salsa20, 64)
CIPHER_SPECIFICS_DEF(sosemanuk, 16)

#undef CIPHER_SPECIFICS_DEF

const cipher_attributes *cipher_attributes_map[LAST_CIPHER+1] = {
    &hc128_cipher,
    &rabbit_cipher,
    &salsa20_cipher,
    &sosemanuk_cipher
};

void *
buffered_get_cipher_state(buffered_state *full_state)
{
  return (uint8_t*)full_state + sizeof(buffered_state);
}

void
buffered_init_header(buffered_state *state_header, cipher_type cipher)
{
  state_header->cipher = cipher_attributes_map[(int)cipher];
  state_header->available_count = 0;
}

void
buffered_reset(buffered_state *state_header)
{
  state_header->available_count = 0;
}

static int
is_aligned(const void *ptr)
{
  return ((unsigned long)ptr & 3u) == 0; /* Multiple of 4 */
}

static uint8_t *
memxor(uint8_t *dest, const uint8_t *mask, size_t n)
{
  size_t i;
  if(UNALIGNED_ACCESS || (is_aligned(dest) && is_aligned(mask)))
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

typedef void *(*memop_func)(void *dest, const void *src, size_t n);
static const memop_func memops[] =
  {
    memcpy,
    (memop_func)memxor
  };

void
buffered_action(buffered_state *full_state, uint8_t *stream, size_t len, buffered_ops op)
{
  const uint8_t chunk_size = full_state->cipher->chunk_size;

  uint8_t *cbuffer = (uint8_t*)full_state + full_state->cipher->buffer_offset;
  assert(is_aligned(cbuffer) && "Unaligned buffered_state");

  void *cipher_state = buffered_get_cipher_state(full_state);

  uint8_t count = full_state->available_count;

  /* First, use up whatever is in the buffer */
  if(count > 0)
    {
      size_t to_copy = min(count, len);
      memops[op](stream, cbuffer + chunk_size - count, to_copy);
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
	full_state->cipher->extract_func(cipher_state, stream);
	stream += chunk_size;
      }
  else
    for(; i > 0; --i)
      {
	full_state->cipher->extract_func(cipher_state, cbuffer);
	memops[op](stream, cbuffer, chunk_size);
	stream += chunk_size;
      }

  /* Finally, extract the next chunk to state buffer, and fill up the
   * remaining non-multiple bytes. */
  if(remainder)
    {
      full_state->cipher->extract_func(cipher_state, cbuffer);
      memops[op](stream, cbuffer, remainder);
      count = chunk_size - remainder;
    }

  full_state->available_count = count;
}

void buffered_skip(buffered_state *full_state, size_t len)
{
  const uint8_t chunk_size = full_state->cipher->chunk_size;
  uint8_t *cbuffer = (uint8_t*)full_state + full_state->cipher->buffer_offset;
  void *cipher_state = buffered_get_cipher_state(full_state);

  if(len <= full_state->available_count)
    full_state->available_count -= len;
  else
    {
      len -= full_state->available_count;
      full_state->available_count = 0;
      
      int i;
      uint8_t remainder = len % chunk_size;
      for(i = len / chunk_size; i > 0; --i)
	full_state->cipher->extract_func(cipher_state, cbuffer);

      if(remainder)
	{
	  full_state->cipher->extract_func(cipher_state, cbuffer);
	  full_state->available_count = chunk_size - remainder;
	}
    }
}
