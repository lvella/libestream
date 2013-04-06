#include <stdint.h>

/* TODO: deal with systems that do not have htole16 and htole32. */
#define _BSD_SOURCE
#include <endian.h>
#undef _BSD_SOURCE

#include "buffered.h"

#define WORK_BUFFER_SIZE (4096)

void
enc_sign_send(signer_context *ctx, void *send_param, const uint8_t *msg_buff, uint32_t len)
{
  uint8_t buffer[WORK_BUFFER_SIZE];
  uint16_t buff_used;
  uint32_t processed_count = 0;

  uint32_t sent_msg_bytes = 0;

  {
    uint32_t ordered_len = htole32(len);
    memcpy(buffer, &ordered_len, 4);
    buff_used = 4;
  }

  /* If message is greater than 1024 bytes, a MAC just for the size is generated, to
   * avoid DoS by an attacker flipping higher order bits of the size, and leaving
   * the receiver waiting indefinitely. */
  if(len > 1024) {
    ctx->uhash_init(ctx->uhash_state);
    ctx->uhash_update(ctx->uhash_key, ctx->cipher_state, buffer, buff_used);
    ctx->uhash_finish(ctx->uhash_key, ctx->uhash_state, &buffer[buff_used]);

    /* The maximum possible value to used is 10. */
    buff_used += ctx->uhash_byte_size;
  }

  /* Initial send buffer filling. */
  {
    uint16_t space_left = WORK_BUFFER_SIZE - buff_used;
    uint16_t to_copy = min(len, space_left);
    memcpy(&buffer[buff_used], msg_buff, to_copy);
    processed_count += to_copy;
    buff_used += to_copy;
  }

  ctx->uhash_init(ctx->uhash_state);
  while(buff_used > 0) {
    /* Calculates MAC so far. */
    ctx->uhash_update(ctx->uhash_key, ctx->cipher_state, buffer, buff_used);

    if(processed_count < len) {
      /* Encrypt, send, and fill the buffer again. */
      buffered_action(ctx->cipher_state, buffer, buff_used, BUFFERED_ENCDEC);
      ctx->send_callback(send_param, buffer, buff_used);

      buff_used = min(len, WORK_BUFFER_SIZE);
      memcpy(buffer, msg_buff + processed_count, buff_used);
      processed_count += buff_used;
    } else {
      /* Finishes the MAC, and send the remaining buffer and MAC. */
      uint16_t space_left = WORK_BUFFER_SIZE - buff_used;
      if(space_left >= ctx->uhash_byte_size) {
	/* Take the MAC into the same buffer. */
	ctx->uhash_finish(ctx->uhash_key, ctx->uhash_state, &buffer[buff_used]);
	buff_used += ctx->uhash_byte_size;

	/* Encrypt everything and send. */
	buffered_action(ctx->cipher_state, buffer, buff_used, BUFFERED_ENCDEC);
	ctx->send_callback(send_param, buffer, buff_used);
      } else {
	/* MAC doesn't fit in buffer, encrypt it and send separately.
	 * First the last chunk of the message... */
	buffered_action(ctx->cipher_state, buffer, buff_used, BUFFERED_ENCDEC);
	ctx->send_callback(send_param, buffer, buff_used);

	/* ...then the MAC. */
	ctx->uhash_finish(ctx->uhash_key, ctx->uhash_state, buffer);
	buffered_action(ctx->cipher_state, buffer, ctx->uhash_byte_size, BUFFERED_ENCDEC);
	ctx->send_callback(send_param, buffer, ctx->uhash_byte_size);
      }
      buff_used = 0;
    }
  }
}

size_t recv_dec_verify(signer_context *ctx, int socket, uint8_t **buffer)
{

}
