/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "salsa20.h"

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

static void
test(const char *input, salsa20_variant variant)
{
  int k = 0;
  while(input = strstr(input, "key = ")) {
    input += 6;

    uint8_t key[32];
    int keysize = read_hex_bytes(&input, key, 32);

    input = strstr(input, "IV = ");
    input += 5;

    uint8_t iv[8];
    read_hex_bytes(&input, iv, 8);

    salsa20_state master, ivstate;
    salsa20_init_key(&master, variant, key,
		     keysize == 16 ? SALSA20_128_BITS
		     : SALSA20_256_BITS);
    salsa20_init_iv(&ivstate, &master, iv);

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

      do
	{
	  salsa20_extract(&ivstate, stream);
	  gen_bytes += 64;
	}
      while(gen_bytes <= from);

      uint8_t rstream[64];
      read_hex_bytes(&input, rstream, 64);
      printf("Salsa20/%d, %d, %d: ", 2*variant, k, i);
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
}

int main()
{
  const char* filenames[] =
    {"tests/salsa20-8_test_vec.txt",
     "tests/salsa20-12_test_vec.txt",
     "tests/salsa20-20_test_vec.txt"};

  const salsa20_variant variants[] = 
    {SALSA20_8, SALSA20_12, SALSA20_20};

  int i;
  for(i = 0; i < 3; ++i)
    {
      FILE *fp = fopen(filenames[i], "r");
      fseek(fp, 0, SEEK_END);
      size_t size = ftell(fp);
      rewind(fp);

      char *data = malloc(size+1);
      fread(data, 1, size, fp);
      fclose(fp);
      data[size] = '\0';

      test(data, variants[i]);

      free(data);
    }
}
