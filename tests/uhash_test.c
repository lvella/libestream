#include <stdio.h>
#include <string.h>
#include "uhash_vec_keys.h"

int main()
{
  uhash_64_state s;
  uhash_64_init(&s);

  int i;
  for(i = 0; i < 500; ++i)
    uhash_64_update(&key_64, &s, "abc", 3);

  uint8_t out[8];
  uhash_64_finish(&key_64, &s, out);

  putchar(':');
  for(i = 0; i < 8; ++i)
    printf("%02X", out[i]);
  putchar('\n');

  uint8_t full_str[1500];
  for(i = 0; i < 500; ++i)
    memcpy(&full_str[i*3], "abc", 3);

  uhash_64_init(&s);
  uhash_64_update(&key_64, &s, full_str, 1500);
  uhash_64_finish(&key_64, &s, out);
  putchar(':');
  for(i = 0; i < 8; ++i)
    printf("%02X", out[i]);
  putchar('\n');
}
