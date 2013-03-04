#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "uhash_vec_keys.h"

void print_hex(uint8_t *str, size_t len, uint32_t *pad)
{
  putchar(':');
  int i, j;
  for(i = 0; i < len / 4; ++i)
    {
      uint32_t p = htonl(pad[i]);
      uint8_t *bp = (uint8_t*)&p;
      for(j = 0; j < 4; ++j)
	printf("%02X", str[i*4 + j] ^ bp[j]);
    }
  putchar('\n');
}

void run_test(char* name, char *msg, size_t len)
{
  printf("Message: %s\n", name);

  uint8_t out[16];
  
  {
    fputs("32", stdout);
    uhash_32_state s32;
    uhash_32_init(&s32);
    uhash_32_update(&key_32, &s32, msg, len);
    uhash_32_finish(&key_32, &s32, out);
    print_hex(out, 4, &pad32);
  }

  {
    fputs("64", stdout);
    uhash_64_state s64;
    uhash_64_init(&s64);
    uhash_64_update(&key_64, &s64, msg, len);
    uhash_64_finish(&key_64, &s64, out);
    print_hex(out, 8, pad64);
  }

  {
    fputs("96", stdout);
    uhash_96_state s96;
    uhash_96_init(&s96);
    uhash_96_update(&key_96, &s96, msg, len);
    uhash_96_finish(&key_96, &s96, out);
    print_hex(out, 12, pad96);
  }

  {
    fputs("128", stdout);
    uhash_128_state s128;
    uhash_128_init(&s128);
    uhash_128_update(&key_128, &s128, msg, len);
    uhash_128_finish(&key_128, &s128, out);
    print_hex(out, 16, pad128);
  }
}

int main()
{
  run_test("<empty>", "", 0); /* Fail. */

  run_test("'a' * 3", "aaa", 3);

  char *buf = malloc(1 << 25);
  memset(buf, 'a', 1 << 25);

  run_test("'a' * 2^10", buf, 1 << 10);
  run_test("'a' * 2^15", buf, 1 << 15);
  run_test("'a' * 2^20", buf, 1 << 20);
  run_test("'a' * 2^25", buf, 1 << 25); /* Fail. */

  run_test("'abc' * 1", "abc", 3);

  int i;
  for(i = 0; i < 500; ++i)
    memcpy(&buf[i*3], "abc", 3);

  run_test("'abc' * 500", buf, 1500);
}
