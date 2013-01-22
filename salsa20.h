#pragma once

#include <inttypes.h>

typedef enum {
  SALSA20_8 = 4,
  SALSA20_12 = 6,
  SALSA20_20 = 10
} salsa20_variant;

typedef enum {
  SALSA20_128_BITS,
  SALSA20_256_BITS
} salsa20_key_size;

typedef struct {
  union {
    uint32_t bit32[16];
    uint64_t bit64[8];
  } hash_input;
  char variant;
} salsa20_state;

/** Initialize the Salsa20 master state with key and variant type.
 *
 * Contrary to Rabbit cypher, the state initialized by this function can
 * *NOT* be used directly in the encryption/decryption process. It MUST
 * be used to generate the encription states based on an Initialization
 * Vector (IV). See function salsa20_init_iv().
 *
 * @param state The unintialized state.
 * @param variant One of SALSA20_8, SALSA20_12 or SALSA20_20 enum values,
 * representing the number of rounds of the hash function, the bigger, the
 * slower and safer. eSTREAM Portifolio specifies SALSA20_12 variant
 * (written as Salsa20/12). As expected, you must use the same variant in
 * order to encrypt/decrypt the message.
 * @param key 16 or 32 bytes buffer of the 128-bit or 256-bit key. The buffer
 * must be aligned to at least 4 bytes (depending on the plataform it may or
 * may not work with unaligned memory).
 * @param key_size One of the enum values SALSA20_128_BITS or SALSA20_256_BITS
 * giving the size of the buffer provided as key (16 or 32 bytes, respectvely).
 */
void salsa20_init_key(salsa20_state *state, salsa20_variant variant,
		      const uint8_t *key, salsa20_key_size key_size);

/** Initialize the Salsa20 state for encryption/decryption with IV.
 *
 * The master state initialized in salsa20_init_key() can be reused many
 * times to generate different encryption states based on different
 * Initialization Vectors (IVs). You must initialise a state with this
 * function in order to encrypt/decrypt, otherwise the output stream will
 * have undefined value.
 *
 * Calling this function implicitly initializes the state's counter to 0,
 * thus preparing it to generate the stream from the beginning. See
 * salsa20_set_counter().
 *
 * Notice that an IV should never be reused.
 *
 * @param iv_state The output state, to be initialized with the IV.
 * @param master The master state, already initialized with the key.
 * @param iv 8 bytes buffer containing the IV. Must be 4 byte aligned.
 */
void salsa20_init_iv(salsa20_state *iv_state, const salsa20_state *master,
		     const uint8_t *iv);

/** Set what chunk of the stream to generate.
 *
 * Salsa20 has the interesting property of being able to generate, in constant
 * time, any 64-byte chunk of the full 2^70 bytes output stream. This function
 * sets the internal counter state to a value so the next call to
 * salsa20_extract() will generate from that chunk onwards.
 *
 * @param state The state whose counter will be set.
 * @param counter The 64-byte chunk's index to be generated next.
 */
void salsa20_set_counter(salsa20_state *state, uint64_t counter);

/** Calculates the next hash output of the algorithm.
 *
 * Also increments the internal counter, so that sucessive calls generates
 * correct sequenced output.
 *
 * @param state The algorithm state.
 * @param stream A 64 byte buffer where the generated stream will be stored.
 * Must be 4 byte aligned.
 */
void salsa20_extract(salsa20_state *state, uint8_t *stream);
