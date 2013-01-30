#pragma once

#include <inttypes.h>

typedef void (*extract_func_type)(void *state, uint8_t *stream);

typedef struct
{
  extract_func_type extract_func;
  uint16_t count_offset;
  uint16_t buffer_offset;
  uint8_t chunk_size;
} cipher_attributes;

#define CIPHER_SPECIFICS_DECL(name,size)	\
  typedef struct {				\
    name##_state state;				\
    /* Using uint32_t to ensure alignment: */	\
    uint32_t buffer[(size)/4];			\
    uint8_t available_count;			\
  } name##_state_buffered;			\
  extern const cipher_attributes name##_cipher;

CIPHER_SPECIFICS_DECL(hc128, 4)
CIPHER_SPECIFICS_DECL(rabbit, 16)
CIPHER_SPECIFICS_DECL(salsa20, 64)
CIPHER_SPECIFICS_DECL(sosemanuk, 16)

#undef CIPHER_SPECIFICS_DECL

void buffered_extract(const cipher_attributes *cipher, void *buffered_state,
		      uint8_t *buffer, size_t len);
