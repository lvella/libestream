/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "umac_vec_keys.h"

static const uhash_key * const keys[] = {
    (const uhash_key *)&key_32,
    (const uhash_key *)&key_64,
    (const uhash_key *)&key_96,
    (const uhash_key *)&key_128
};

void print_hex(uint8_t *str, size_t len, uint32_t *pad)
{
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

void run_test(char* name, char *char_msg, size_t len)
{
  uint8_t *msg = (uint8_t*)char_msg;
  uint8_t out[16];
  
  union {
    uhash_32_state s32;
    uhash_64_state s64;
    uhash_96_state s96;
    uhash_128_state s128;
  } state;

  uhash_state *state_ptr = (uhash_state *)&state;

  int i;

  printf("Message: %s\n", name);

  for(i = 0; i < 4; ++i)
  {
    printf("%d:", (i+1) * 32);
    uhash_init((uhash_type)i, state_ptr);
    uhash_update(keys[i], state_ptr, msg, len);
    uhash_finish(keys[i], state_ptr, out);
    print_hex(out, (i+1)*4, pads[i]);
  }
}

void std_test()
{
  run_test("<empty>", "", 0);


  char *buf = malloc(1 << 25);
  memset(buf, 'a', 1 << 25);

  run_test("'a' * 3", buf, 3);
  run_test("'a' * 2^10", buf, 1 << 10);
  run_test("'a' * 2^15", buf, 1 << 15);
  run_test("'a' * 2^20", buf, 1 << 20);
  run_test("'a' * 2^25", buf, 1 << 25);

  run_test("'abc' * 1", "abc", 3);

  int i;
  for(i = 0; i < 500; ++i)
    memcpy(&buf[i*3], "abc", 3);

  run_test("'abc' * 500", buf, 1500);
}

int main(int argc, char *argv[])
{
  if(argc <= 1) {
    std_test();
    return 0;
  } else if(argc != 3) {
    fprintf(stderr, "Usage:\n  %s <message> <taglen>\nwhere <taglen> is one of 32, 64, 96 or 128\n", argv[0]);
    return 1;
  }

  {
    union {
      uhash_32_state s32;
      uhash_64_state s64;
      uhash_96_state s96;
      uhash_128_state s128;
    } state;

    uhash_state *state_ptr = (uhash_state *)&state;

    int i = atoi(argv[2]) / 32 - 1;
    uint8_t out[16];

    if(i < 0 || i > 3 || (atoi(argv[2]) % 32)) {
      fputs("Invalid taglen, must be one of 32, 64, 96 or 128\n", stderr);
      return 1;
    }

    uhash_init((uhash_type)i, state_ptr);
    uhash_update(keys[i], state_ptr, argv[1], strlen(argv[1]));
    uhash_finish(keys[i], state_ptr, out);
    print_hex(out, (i+1)*4, pads[i]);
  }
}
