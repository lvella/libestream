/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#pragma once

#include <inttypes.h>

typedef struct
{
  uint32_t x[8];
  uint32_t c[8];
  uint8_t carry;
} rabbit_state;

/** Initialize the Rabbit master state with key.
 *
 * The state initialized by this function can be used directly in the
 * encryption/decryption process, or can be used to generate other encription
 * states based on an Initialization Vector (IV). See function
 * rabbit_init_iv().
 *
 * @param state The unintialized state.
 * @param key 16 bytes buffer of the 128-bit key. The buffer must be aligned
 * to at least 4 bytes (depending on the plataform it may or may not work with
 * unaligned memory).
 */
void rabbit_init_key(rabbit_state *state, const uint8_t *key);

/** Initialize the Rabbit state for encryption/decryption.
 *
 * The master state initialized in rabbit_init_key() can be reused many
 * times to generate different encryption states based on different
 * Initialization Vectors (IVs).
 *
 * Notice: an IV should never be reused.
 *
 * @param iv_state The output state, to be initialized with the IV.
 * @param master The master state, already initialized with the key.
 * @param iv 8 bytes buffer containing the IV. Must be 4 byte aligned.
 */
void rabbit_init_iv(rabbit_state *iv_state, const rabbit_state *master,
		    const uint8_t *iv);

/** Performs one round of the algorithm.
 *
 * @param state The algorithm state.
 * @param stream A 16 byte buffer where the generated stream will be stored.
 * Must be 4 byte aligned.
 */
void rabbit_extract(rabbit_state *state, uint8_t *stream);
