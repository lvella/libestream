#pragma once

#include "buffered.h"
#include "umac.h"

typedef void (*uhash_init_func)(void *state);
typedef void (*uhash_update_func)(const void *key, void *state, const uint8_t *string, size_t len);
typedef void (*uhash_finish_func)(const void *key, void *state, uint8_t *out);

typedef void (*io_callback_func)(void *parameter, uint8_t *buffer, uint16_t len);

typedef struct
{
  buffered_state *cipher_state;

  /** Either low-level sending or receiving function. */
  io_callback_func io_callback;

  void *uhash_key;
  void *uhash_state;
  uhash_init_func uhash_init;
  uhash_update_func uhash_update;
  uhash_finish_func uhash_finish;
  uint8_t uhash_byte_size;
} signer_context;

typedef enum
{
  SIGNER_RECV_SUCCESS,
  SIGNER_RECV_VERIFY_FAILED,
  SIGNER_ALLOC_FAILED
} SignerReceiveStatus;

/** Encrypt, sign and send a buffer via a socket.
 *
 */
void signed_send(signer_context *ctx, void *send_param, const uint8_t *buffer, uint32_t len);

/** Receive, decrypt and verify a buffer sent via socket.
 *
 * @param buffer A pointer to where to store the address of the newly allocated buffer
 * containing the received message. Must be freed with free().
 */
SignerReceiveStatus signed_recv(signer_context *ctx, void *recv_param, uint8_t **buffer, uint32_t *size);
