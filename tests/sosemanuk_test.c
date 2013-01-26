/* Author: Lucas Clemente Vella
 * Source code placed into public domain. */

#include <stdio.h>
#include "sosemanuk.h"

int main()
{
  uint8_t mkey[2][16] =
    {{0xA7, 0xC0, 0x83, 0xFE,
      0xB7,    0,    0,    0,
         0,    0,    0,    0,
         0,    0,    0,    0},
     {0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xAA, 0xBB,
      0xCC, 0xDD, 0xEE, 0xFF}};
  uint8_t keylen[2] = {40, 128};
  
  uint8_t iv[2][16] =
    {{0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77, 
      0x88, 0x99, 0xAA, 0xBB,
      0xCC, 0xDD, 0xEE, 0xFF},
     {0x88, 0x99, 0xAA, 0xBB,
      0xCC, 0xDD, 0xEE, 0xFF,
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77}};
  int k;
  for(k = 0; k < 2; ++k) {
    sosemanuk_master_state mstate;
    sosemanuk_init_key(&mstate, mkey[k], keylen[k]);

    sosemanuk_state ivstate;
    sosemanuk_init_iv(&ivstate, &mstate, iv[k]);

    puts("Total output:");
    int i;
    for(i = 0; i < 10; ++i) {
      uint8_t s[16];
      sosemanuk_extract(&ivstate, s);
      int j;
      for(j = 0; j < 16; ++j)
	printf(" %02X", s[j]);
      putchar('\n');
    }
    putchar('\n');
  }
}
