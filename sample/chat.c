/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "protocol.h"

int listening = 0;
struct sockaddr_in addr;

uint8_t key[16];

int sock;

static int parse_args(int argc, char *argv[])
{
  int ip_idx;
  int port_idx;
  int key_idx;

  if(argc < 4)
    return 0;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;

  if(!strcmp(argv[1], "-l")) {
    /* Is listening... */
    listening = 1;

    /* If IP is provided. */
    if(argc == 5) {
      ip_idx = 2;
      port_idx = 3;
      key_idx = 4;
    } else {
      ip_idx = -1;
      port_idx = 2;
      key_idx = 3;
    }
  } else {
    /* Is connecting... */
    ip_idx = 1;
    port_idx = 2;
    key_idx = 3;
  }

  /* Set IP. */
  if(ip_idx >= 0) {
    if(!inet_aton(argv[ip_idx], &addr.sin_addr))
      return 0;
  }

  /* Set port. */
  {
    char *endptr;
    addr.sin_port = htons(strtol(argv[port_idx], &endptr, 0));
    if(!*argv[port_idx] || *endptr)
      return 0;
  }

  /* Set key. */
  {
    int i, j;
    for(i = 0; i < 16; ++i) {
      key[i] = 0;
      for(j = 0; j < 2; ++j) {
	char val = argv[key_idx][2*i + j];
	if(val >= '0' && val <= '9')
	  val -= '0';
	else if(val >= 'a' && val <= 'f')
	  val = (val - 'a') + 10;
	else if(val >= 'A' && val <= 'F')
	  val = (val - 'A') + 10;
	else
	  return 0;
	key[i] = (key[i] * 16) + val;
      }
    }
  }

  return 1;
}

void my_send(int *socket, uint8_t *buffer, uint16_t len)
{
  uint16_t sent = 0;
  do {
    int ret;
    do {
      ret = write(*socket, buffer + sent, len - sent);
    } while(ret < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
    if(ret < 0) {
      perror("Error sending message");
      exit(EXIT_FAILURE);
    }
    sent += ret;
  } while(sent < len);
}

void my_read(int *socket, uint8_t *buffer, uint16_t len)
{
  uint16_t count = 0;
  do {
    int ret;
    do {
      ret = read(*socket, buffer + count, len - count);
    } while(ret < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
    if(ret < 0) {
      perror("Error receiving message");
      exit(EXIT_FAILURE);
    }
    count += ret;
  } while(count < len);
}

typedef struct {
    sosemanuk_buffered_state buffered;
    uhash_64_key uhash_key;
    uhash_64_state uhash_state;
    signer_context signer;
} full_context;

static void signer_setup(full_context *ctx, io_callback_func func)
{
  ctx->signer.cipher_state = (buffered_state *)&ctx->buffered;
  ctx->signer.io_callback = func;
  ctx->signer.mac_key = (uhash_key *)&ctx->uhash_key;
  ctx->signer.mac_state = (uhash_state *)&ctx->uhash_state;

  uhash_key_setup(UHASH_64, ctx->signer.mac_key, ctx->signer.cipher_state);
}

static void *receiver_loop(full_context *inbound)
{
  uint8_t *ptr;
  uint32_t size;

  SignerReceiveStatus ret = signed_recv(&inbound->signer, &sock, &ptr, &size);
  while(ret == SIGNER_RECV_SUCCESS)
  {
    fwrite(ptr, 1, size, stdout);
    fflush(stdout);
    free(ptr);
    ret = signed_recv(&inbound->signer, &sock, &ptr, &size);
  }

  if(ret == SIGNER_RECV_VERIFY_FAILED) {
    fputs("It seems there is an attacker is tampering with the received data.\n", stderr);
  } else {
    fputs("Could not allocate enough memory for incoming message.\n", stderr);
  }
  fputs("Will stop trying to receive anything.\n", stderr);

  return NULL;
}

static void run_communication()
{
  full_context inbound, outbound;
  pthread_t receiver_thread;

  /* IV generation/exchange and initialization of cipher states.
   * Note that an IV must *NEVER* be reused. */
  {
    /* Master state, initialized with the key. */
    sosemanuk_master_state master_state;
    sosemanuk_init_key(&master_state, key, 128);

    /* Generate an outbound IV based on remote peer address,
     * then send and setup state. */
    {
      unsigned int seed = time(NULL);
      int i;
      int size;
      uint32_t iv[4];

      /* Dirty trick to read the address as unsigned ints. */
      union {
        struct sockaddr_in addr;
        unsigned int ints[1];
      } accessor;

      accessor.addr = addr;

      size = 1 + ((sizeof(struct sockaddr_in) - 1) / sizeof(unsigned int));
      for(i = 0; i < size; ++i) {
        seed += accessor.ints[i];
      }

      srand(seed);
      for(i = 0; i < 4; ++i)
	iv[i] = htole32(rand());

      write(sock, iv, 16);
      buffered_init_header(&outbound.buffered.header, SOSEMANUK);
      sosemanuk_init_iv(&outbound.buffered.state, &master_state, (uint8_t*)&iv[0]);
    }

    /* Receive inbound IV and setup state. */
    {
      uint8_t iv[16];
      read(sock, iv, 16);
      buffered_init_header(&inbound.buffered.header, SOSEMANUK);
      sosemanuk_init_iv(&inbound.buffered.state, &master_state, iv);
    }
  }

  /* Setup UHASH and the signers. */
  signer_setup(&inbound, (io_callback_func)my_read);
  signer_setup(&outbound, (io_callback_func)my_send);

  /* Wait for messages in another thread. */
  pthread_create(&receiver_thread, NULL, (void *(*)(void *))receiver_loop, &inbound);

  /* Loop reading user input and sending messages. */
  {
    uint8_t buff[4096];
    ssize_t count = read(STDIN_FILENO, buff, 4096);
    while(count > 0) {
      signed_send(&outbound.signer, &sock, buff, count);
      count = read(STDIN_FILENO, buff, 4096);
    }
    if(count < 0) {
      perror("Error reading input");
      exit(EXIT_FAILURE);
    }
  }

  close(sock);
  pthread_join(receiver_thread, NULL);
}

int main(int argc, char *argv[])
{
  if(!parse_args(argc, argv))
  {
    fprintf(stderr, "Incorrect parameters!\n"
	"Usage for server:\n  %1$s -l [<address>] <port> <hex_key>\n"
	"usage for client:\n  %1$s <address> <port> <hex_key>\n", argv[0]);
    return EXIT_FAILURE;
  }

  sock = socket(AF_INET, SOCK_STREAM, 0);

  /* Either accept one connection or connect to one remote peer. */
  if(listening) {
    int tmp_sock;
    socklen_t addr_size = sizeof(addr);

    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    listen(sock, 1);
    tmp_sock = accept(sock, (struct sockaddr *)&addr, &addr_size);
    close(sock);

    sock = tmp_sock;
  } else {
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(ret < 0)
      perror("Could not connect");
  }

  /* Disable Nagle algorithm. */
  {
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
  }

  run_communication();

  close(sock);

  return EXIT_SUCCESS;
}
