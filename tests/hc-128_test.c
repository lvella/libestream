/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hc-128.h"

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
test(const char *input)
{
  int k = 0;
  while(input = strstr(input, "key = ")) {
    input += 6;

    uint8_t key[16];
    read_hex_bytes(&input, key, 16);

    input = strstr(input, "IV = ");
    input += 5;

    uint8_t iv[16];
    read_hex_bytes(&input, iv, 16);

    hc128_state state;
    hc128_init(&state, key, iv);

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

      while(gen_bytes < from)
	{
	  hc128_extract(&state, stream);
	  gen_bytes += 4;
	}

      int j;
      for(j = 0; j < 16; ++j)
	{
	  hc128_extract(&state, &stream[j*4]);
	  gen_bytes += 4;
	}

      uint8_t rstream[64];
      read_hex_bytes(&input, rstream, 64);
      printf("HC-128, %d, %d: ", k, i);
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
  const char* filename = "tests/hc-128_test_vec.txt";

  int i;
  FILE *fp = fopen(filename, "r");
  fseek(fp, 0, SEEK_END);
  size_t size = ftell(fp);
  rewind(fp);

  char *data = malloc(size+1);
  fread(data, 1, size, fp);
  fclose(fp);
  data[size] = '\0';

  test(data);

  free(data);
}
