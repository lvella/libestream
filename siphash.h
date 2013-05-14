#include <stdint.h>

typedef struct {
  uint64_t v[4];
} siphash_key;

typedef struct {
  uint64_t v[4];
  union {
    uint8_t byte[8];
    uint64_t word;
  } buffer;
  size_t byte_count;
} siphash_state;

/**
 * @param key Key structure to be initialized.
 * @param key_value A 16 bytes secret key.
 */
void siphash_key_setup(siphash_key *key, const uint8_t* key_value);

void siphash_init(const siphash_key *key, siphash_state *state);

void siphash_update(siphash_state *state, const uint8_t *input, size_t len);

/**
 * @param output Buffer were will be stored the hash output.
 */
void siphash_finish(siphash_state *state, uint8_t *output);
