/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buffered.h"

static size_t
read_hex_bytes(const char **from, uint8_t *dest, uint8_t max_len)
{
  size_t byte_count = 0;
  int read_bytes;
  unsigned int value;
  while(byte_count < max_len
	&& sscanf(*from, "%2x%n", &value, &read_bytes) == 1)
    {
      *from += read_bytes;
      dest[byte_count++] = value;
    }

  return byte_count;
}

static void
print_hex(uint8_t *stream, size_t size)
{
  int i;
  for(i = 0; i < size; ++i)
    {
      printf("%02X", stream[i]);
      if(i % 16 == 15)
	putchar('\n');
    }
}

typedef void (*init_func) (void *state, uint8_t* key, uint8_t* iv,
			   size_t keylen);

static void
test(const char *name, const char *input, const cipher_attributes *cipher,
     init_func init)
{
  void *state;
  const size_t alignment = sizeof(void*) > 4 ? sizeof(void*) : 4;
  posix_memalign(&state, alignment, cipher->buffered_state_size);

  int k = 0;
  while(input = strstr(input, "key = ")) {
    input += 6;

    uint8_t key[32];
    int keysize = read_hex_bytes(&input, key, 32);

    input = strstr(input, "IV = ");
    input += 5;

    uint8_t iv[32];
    memset(iv, 0, 32);
    read_hex_bytes(&input, iv, 32);

    ((uint8_t*)state)[cipher->count_offset] = 0;
    init(state, key, iv, keysize);

    size_t gen_bytes = 0;
    int i;
    for(i = 0; i < 4; ++i) {
      uint8_t stream[64];
      unsigned int from, to;
      int skip;

      input = strstr(input, "stream[");
      input += 7;

      sscanf(input, "%u..%u%n", &from, &to, &skip);
      input += skip + 4;

      if(gen_bytes < from)
	{
	  size_t ammount = from - gen_bytes;
	  buffered_skip(cipher, state, ammount);
	  gen_bytes += ammount;
	}

      buffered_action(cipher, state, stream, 64, BUFFERED_EXTRACT);
      gen_bytes += 64;

      uint8_t rstream[64];
      read_hex_bytes(&input, rstream, 64);
      printf("%s, %d, %d: ", name, k, i);
      if(memcmp(rstream, stream, 64)) {
        puts("mismatch\n  read:");
	print_hex(rstream, 64);
	puts("  calculated:");
	print_hex(stream, 64);
	exit(1);
      } else {
	puts("match!");
      }
    }

    /* ignore xor digest */
    input = strstr(input, " = ");
    input += 3;

    ++k;
  }

  free(state);
}

static void
perform_test(const char* filename, const cipher_attributes *cipher,
	     init_func init)
{
  FILE *fp = fopen(filename, "r");
  fseek(fp, 0, SEEK_END);
  size_t size = ftell(fp);
  rewind(fp);

  char *data = malloc(size+1);
  fread(data, 1, size, fp);
  fclose(fp);
  data[size] = '\0';

  test(filename, data, cipher, init);

  free(data);
}

static void
init_hc128(hc128_state *state, uint8_t* key,
	   uint8_t* iv, size_t ignore)
{
  hc128_init(state, key, iv);
}

static void
init_rabbit(rabbit_state *state, uint8_t* key,
	   uint8_t* iv, size_t ignore)
{
  rabbit_state master;
  rabbit_init_key(&master, key);
  rabbit_init_iv(state, &master, iv);
}

static void
init_salsa20_8(salsa20_state *state, uint8_t* key,
	       uint8_t* iv, size_t keysize)
{
  salsa20_state master;
  salsa20_init_key(&master, SALSA20_8, key,
		   keysize == 16 ? SALSA20_128_BITS : SALSA20_256_BITS);
  salsa20_init_iv(state, &master, iv);
}

static void
init_salsa20_12(salsa20_state *state, uint8_t* key,
	       uint8_t* iv, size_t keysize)
{
  salsa20_state master;
  salsa20_init_key(&master, SALSA20_12, key,
		   keysize == 16 ? SALSA20_128_BITS : SALSA20_256_BITS);
  salsa20_init_iv(state, &master, iv);
}

static void
init_salsa20_20(salsa20_state *state, uint8_t* key,
	       uint8_t* iv, size_t keysize)
{
  salsa20_state master;
  salsa20_init_key(&master, SALSA20_20, key,
		   keysize == 16 ? SALSA20_128_BITS : SALSA20_256_BITS);
  salsa20_init_iv(state, &master, iv);
}

static void
init_sosemanuk(sosemanuk_state *state, uint8_t* key,
	       uint8_t* iv, size_t keysize)
{
  sosemanuk_master_state master;
  sosemanuk_init_key(&master, key, keysize*8);
  sosemanuk_init_iv(state, &master, iv);
}

int main()
{
  perform_test("tests/hc-128_test_vec.txt",
	       &hc128_cipher, (init_func)init_hc128);

  perform_test("tests/rabbit_test_vec.txt",
	       &rabbit_cipher, (init_func)init_rabbit);

  perform_test("tests/salsa20-8_test_vec.txt",
	       &salsa20_cipher, (init_func)init_salsa20_8);
  perform_test("tests/salsa20-12_test_vec.txt",
	       &salsa20_cipher, (init_func)init_salsa20_12);
  perform_test("tests/salsa20-20_test_vec.txt",
	       &salsa20_cipher, (init_func)init_salsa20_20);

  perform_test("tests/sosemanuk_test_vec.txt",
	       &sosemanuk_cipher, (init_func)init_sosemanuk);
}
