#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* TODO: deal with systems that do not have htole16 and htole32. */
#include <endian.h>

#include "protocol.h"

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

  ctx->uhash_init(ctx->uhash_state);
  ctx->uhash_update(ctx->uhash_key, ctx->cipher_state, buffer, buff_used);

  /* If message is greater than 1024 bytes, a MAC just for the size is generated, to
   * avoid DoS by an attacker flipping higher order bits of the size, and leaving
   * the receiver waiting indefinitely. */
  if(len > 1024) {
    ctx->uhash_finish(ctx->uhash_key, ctx->uhash_state, &buffer[buff_used]);
    ctx->uhash_init(ctx->uhash_state);

    /* The maximum possible value of "used" is 10. */
    buff_used += ctx->uhash_byte_size;
  }

  /* Initial send buffer filling. */
  {
    uint16_t to_copy = min(len, WORK_BUFFER_SIZE - buff_used);

    memcpy(&buffer[buff_used], msg_buff, to_copy);
    ctx->uhash_update(ctx->uhash_key, ctx->cipher_state, msg_buff, to_copy);

    processed_count += to_copy;
    buff_used += to_copy;
  }

  /* Encrypt, send, and fill the buffer again. */
  while(processed_count < len) {
      buffered_action(ctx->cipher_state, buffer, buff_used, BUFFERED_ENCDEC);
      ctx->io_callback(send_param, buffer, buff_used);

      buff_used = min(len, WORK_BUFFER_SIZE);
      memcpy(buffer, msg_buff + processed_count, buff_used);
      ctx->uhash_update(ctx->uhash_key, ctx->cipher_state, buffer, buff_used);

      processed_count += buff_used;
  }

  {
    /* Finishes the MAC, and send the remaining buffer and MAC. */
    uint16_t space_left = WORK_BUFFER_SIZE - buff_used;
    if(space_left >= ctx->uhash_byte_size) {
	/* Take the MAC into the same buffer. */
	ctx->uhash_finish(ctx->uhash_key, ctx->uhash_state, &buffer[buff_used]);
	buff_used += ctx->uhash_byte_size;

	/* Encrypt everything and send. */
	buffered_action(ctx->cipher_state, buffer, buff_used, BUFFERED_ENCDEC);
	ctx->io_callback(send_param, buffer, buff_used);
    } else {
	/* MAC doesn't fit in buffer, encrypt it and send separately.
	 * First the last chunk of the message... */
	buffered_action(ctx->cipher_state, buffer, buff_used, BUFFERED_ENCDEC);
	ctx->io_callback(send_param, buffer, buff_used);

	/* ...then the MAC. */
	ctx->uhash_finish(ctx->uhash_key, ctx->uhash_state, buffer);
	buffered_action(ctx->cipher_state, buffer, ctx->uhash_byte_size, BUFFERED_ENCDEC);
	ctx->io_callback(send_param, buffer, ctx->uhash_byte_size);
    }
  }
}

static int
mac_verify(signer_context *ctx, void *recv_param)
{
  uint8_t mac_recv[16]; /* 16 bytes (128 bits) is the greatest UMAC tag possible */
  uint8_t mac_calc[16];

  ctx->io_callback(recv_param, mac_recv, ctx->uhash_byte_size);
  buffered_action(ctx->cipher_state, mac_recv, ctx->uhash_byte_size, BUFFERED_ENCDEC);

  ctx->uhash_finish(ctx->uhash_key, ctx->uhash_state, mac_calc);

  return memcmp(mac_recv, mac_calc, ctx->uhash_byte_size) == 0;
}

ReceiveStatus
recv_dec_verify(signer_context *ctx, void *recv_param, uint8_t **buffer, uint32_t *size)
{
  *buffer = NULL;

  ctx->io_callback(recv_param, (uint8_t*)size, 4);
  buffered_action(ctx->cipher_state, (uint8_t*)size, 4, BUFFERED_ENCDEC);

  ctx->uhash_init(ctx->uhash_state);
  ctx->uhash_update(ctx->uhash_key, ctx->cipher_state, (uint8_t*)size, 4);

  *size = le32toh(*size);
  if(*size > 1024) {
      if(!mac_verify(ctx, recv_param))
	return FAILED_MAC_VERIFY;

      ctx->uhash_init(ctx->uhash_state);
  }

  /* Size was properly signed, we can malloc. */
  *buffer = malloc(*size);
  if(!*buffer)
    return MESSAGE_ALLOCATION_FAILED;

  {
      uint32_t received = 0;

      /* We receive and decode in chunks in order to optimize IO/CPU time usage
       * (i.e. does not have to wait IO to finish before start CPU processing). */
      while(received < *size) {
	  uint8_t *ptr = *buffer + received;
	  uint16_t to_recv = min(WORK_BUFFER_SIZE, *size - received);
	  ctx->io_callback(recv_param, ptr, to_recv);
	  received += to_recv;

	  buffered_action(ctx->cipher_state, ptr, to_recv, BUFFERED_ENCDEC);
	  ctx->uhash_update(ctx->uhash_key, ctx->cipher_state, ptr, to_recv);
      }
  }

  if(!mac_verify(ctx, recv_param)) {
      free(*buffer);
      *buffer = NULL;
      return FAILED_MAC_VERIFY;
  }

  return SUCCESS;
}
