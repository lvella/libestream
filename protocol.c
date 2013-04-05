#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "buffered.h"

size_t enc_sign_send(signer_context *ctx, int socket, uint8_t *buffer, uint32_t len)
{
  uint32_t sent_msg_bytes = 0;

  {
    uint8_t header[10];
    uint8_t used;

    uint16_t nbo_len;
    if(len < UINT16_MAX) {
	/* If message smaller than UINT16_MAX, use 2 bytes to encode the length. */
	nbo_len = htons(len);
	used = 2;
    } else {
	/* Otherwise, mark that there is a 4 byte size following. */
	nbo_len = UINT16_MAX;
	uint32_t nbo_full_len = htonl(len);
	memcpy(header+2, &nbo_full_len, 4);
	used = 6;
    }
    memcpy(header, &nbo_len, 2);

    /* If message is greater than 1024, a MAC just for the size is generated, to
     * avoid DoS by an attacker flipping higher order bits of the size, and leaving
     * the receiver waiting indefinitely. */
    if(len > 1024) {
	ctx->uhash_init(ctx->uhash_state);
	ctx->uhash_update(ctx->uhash_key, ctx->cipher_state, header, used);
	ctx->uhash_finish(ctx->uhash_key, ctx->uhash_state, &header[used]);

	/* The maximum possible value to used is 10. */
	used += ctx->uhash_byte_size;
    }

    buffered_action(ctx->cipher_state, header, used, BUFFERED_ENCDEC);
    /* TODO: treat the return value. */
    send(socket, header, used, MSG_MORE);
  }

  /* TODO: to be continued... */
}

size_t recv_dec_verify(signer_context *ctx, int socket, uint8_t **buffer)
{

}
