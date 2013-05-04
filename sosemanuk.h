/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#pragma once

#include <stdlib.h>
#include <inttypes.h>

typedef struct
{
  uint32_t r[2];
  uint32_t s[10];
  uint8_t t;
} sosemanuk_state;

typedef struct
{
  uint32_t k[100];
} sosemanuk_master_state;

/** Initialize the Sosemanuk master state with key.
 *
 * The state initialized by this function is used to generate encryption
 * states based on an Initialization Vector (IV). See function
 * sosemanuk_init_iv().
 *
 * @param s The uninitialized state.
 * @param key Buffer containing the key. The buffer must be aligned to at
 * least 4 bytes (depending on the platform it may or may not work with
 * unaligned memory). Its size, in bytes, must be bitlength / 8.
 * @param bitlength The size of the key in bits. The initialization procedure
 * can take any amount from 0 (useless) to 256 bits, but the algorithm only
 * claim security for 128 bits (16 bytes) keys, and explicitly estates that
 * there is no guarantee of greater security if a bigger key is used. So, just
 * stick with 128.
 */
void sosemanuk_init_key(sosemanuk_master_state *state,
			const uint8_t *key, size_t bitlength);

/** Initialize the Sosemanuk state as for encryption.
 *
 * The master state initialized in sosemanuk_init_key() can be reused many
 * times to generate different encryption states based on different
 * Initialization Vectors (IVs).
 *
 * Notice: an IV should never be reused.
 *
 * @param iv_state The output state, to be initialized with the IV.
 * @param master The master state, already initialized with the key.
 * @param iv A 16 bytes buffer containing the IV. Must be 4 byte aligned.
 */
void sosemanuk_init_iv(sosemanuk_state *iv_state,
		       const sosemanuk_master_state *master,
		       const uint8_t *iv);

/** Performs one round of the algorithm.
 *
 * @param state The algorithm state.
 * @param stream A 16 bytes buffer where the generated stream will be stored.
 * Must be 4 byte aligned.
 */
void sosemanuk_extract(sosemanuk_state *state, uint8_t *stream);
